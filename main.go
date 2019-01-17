package main

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/apex/log"
	jsonloghandler "github.com/apex/log/handlers/json"
	"github.com/apex/log/handlers/text"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/customer"
	"github.com/stripe/stripe-go/sub"
	"github.com/stripe/stripe-go/webhook"
	"gocloud.dev/blob"
	"gocloud.dev/blob/s3blob"
)

var bucket = "uneet-checkout-test"
var views = template.Must(template.ParseGlob("templates/*.html"))

func init() {
	if os.Getenv("UP_STAGE") != "" {
		log.SetHandler(jsonloghandler.Default)
	} else {
		log.SetHandler(text.Default)
	}
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
}

func main() {
	addr := ":" + os.Getenv("PORT")
	app := mux.NewRouter()
	app.HandleFunc("/", index)
	app.HandleFunc("/logout", deletecookie)
	app.HandleFunc("/hook", hook)
	app.HandleFunc("/admin/missingsubs", missingsubs)
	app.HandleFunc("/success", success)
	app.HandleFunc("/cancel", cancel)
	app.HandleFunc("/login", getlogin).Methods("GET")
	app.HandleFunc("/login", postlogin).Methods("POST")

	if err := http.ListenAndServe(addr, app); err != nil {
		log.WithError(err).Fatal("error listening")
	}
}

func routeLog(r *http.Request) *log.Entry {
	l := log.WithFields(log.Fields{
		"method":     r.Method,
		"requestURI": r.RequestURI,
		"referer":    r.Referer(),
		"ua":         r.UserAgent(),
	})
	return l
}

func missingsubs(w http.ResponseWriter, r *http.Request) {
	type customers struct{ Customers []*stripe.Customer }
	log.Info("missing subs")

	var missingSubs customers

	i := customer.List(&stripe.CustomerListParams{})
	for i.Next() {
		c := i.Customer()
		if len(c.Subscriptions.Data) == 0 {
			log.WithField("customerID", c.ID).Info("no subscribers")
			missingSubs.Customers = append(missingSubs.Customers, c)
		}
	}
	views.ExecuteTemplate(w, "customers.html", missingSubs)
}

// User waits here until the Web hook comes in updating the s3://$bucket/$email file
func success(w http.ResponseWriter, r *http.Request) {
	log := routeLog(r)
	log.Info("success")
	views.ExecuteTemplate(w, "success.html", nil)
}

func cancel(w http.ResponseWriter, r *http.Request) {
	email, err := r.Cookie("email")
	if err != nil || email.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	subID, err := load(email.Value)
	if err != nil {
		log.WithField("email", email.Value).Errorf("Failed to load subID")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log := log.WithFields(log.Fields{
		"subID": subID,
		"email": email.Value,
	})

	_, err = sub.Cancel(string(subID), nil)
	if err != nil {
		log.Error("failed to cancel")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info("cancelled")
	err = del(email.Value)
	if err != nil {
		log.Errorf("failed to remove s3://%s/%s", bucket, email.Value)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info("removed S3 user record")
	http.Redirect(w, r, "/", http.StatusFound)
}

func index(w http.ResponseWriter, r *http.Request) {
	email, err := r.Cookie("email")
	if err != nil || email.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	subID, err := load(email.Value)
	if err != nil {
		log.WithField("email", email.Value).Warnf("No record: %s", err)
	}

	views.ExecuteTemplate(w, "index.html", struct {
		Email        string
		SubscriberID string
	}{
		Email:        email.Value,
		SubscriberID: subID,
	})
}

func getlogin(w http.ResponseWriter, r *http.Request) {
	views.ExecuteTemplate(w, "login.html", nil)
}

func postlogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	http.SetCookie(w, &http.Cookie{
		Name:  "email",
		Value: email,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func del(key string) (err error) {
	if key == "" {
		return fmt.Errorf("Empty key")
	}
	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		log.Errorf("Failed to setup bucket: %s", err)
		return err
	}
	err = b.Delete(ctx, key)
	if err != nil {
		log.Errorf("Failed to delete: %s", key)
	}
	return
}

func save(key string, payload string) (err error) {
	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		log.Errorf("Failed to setup bucket: %s", err)
		return err
	}
	err = b.WriteAll(ctx, key, []byte(payload), nil)
	if err != nil {
		log.Errorf("Failed to write to bucket: %s", err)
		return err
	}
	log.Infof("Wrote out to s3://%s/%s", bucket, key)
	return nil
}

func load(key string) (payload string, err error) {
	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		return payload, errors.Wrap(err, "bucket setup")
	}

	r, err := b.NewReader(ctx, key, nil)
	if err != nil {
		return payload, errors.Wrap(err, "no reader")
	}

	// https://godoc.org/gocloud.dev/blob#Bucket.ReadAll
	payloadbytes, err := ioutil.ReadAll(r)
	if err != nil {
		return payload, errors.Wrap(err, "failed to read")
	}
	payload = string(payloadbytes)

	log.Infof("Read from to s3://%s/%s = %q", bucket, key, payload)

	return

}

func hook(w http.ResponseWriter, r *http.Request) {

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to parse body: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), os.Getenv("WH_SIGNING_SECRET"))
	if err != nil {
		log.Errorf("Failed to verify signature: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Debugf("Received signed event: %#v", event)

	switch event.Type {
	case "customer.subscription.created":
		log.Infof("YAY YAY YAY %s", event.Type)
	case "checkout_beta.session_succeeded":
		log.Infof("%s", event.Type)
		subID, ok := event.Data.Object["subscription"].(string)
		if !ok {
			log.Errorf("Failed to retrieve subscription id from %s", event.ID)
			return
		}
		cust, err := sub2customer(subID)
		if err != nil {
			log.Errorf("Failed to retrieve customer email from %s", subID)
			return
		}
		// We save the subscription ID
		err = save(cust.Email, subID)
		if err != nil {
			log.Errorf("Failed to record customer %s as subscribing to %s", cust.Email, subID)
			return
		}
	default:
		log.Infof("Ignoring: %s", event.Type)
	}
	w.WriteHeader(http.StatusOK)
}

// Given a subscription ID, look up the customer, namely for their email address which is used as the identifier
func sub2customer(subID string) (c *stripe.Customer, err error) {
	s, err := sub.Get(subID, nil)
	if err != nil {
		log.Errorf("Failed to retrieve subscription id %s", subID)
		return
	}
	log.Debugf("Subscription info: %#v", s)
	log.Debugf("Customer info from subscription: %#v", s.Customer)
	c, err = customer.Get(s.Customer.ID, nil)
	if err != nil {
		log.Errorf("Failed to retrieve customer id %s", s.Customer.ID)
		return
	}
	log.Infof("Customer info: %#v", c)
	return c, err
}

// To log out
func deletecookie(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     "email",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Using the AWS cloud
func setupAWS(ctx context.Context, bucket string) (b *blob.Bucket, err error) {
	sess := session.New()
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = "uneet-dev"
	}
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			// If you want to set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY envs
			&credentials.EnvProvider{},
			// For when I use cmd/
			&credentials.SharedCredentialsProvider{Filename: "", Profile: profile},
			// IIUC, this is how IAM role is assumed in the Lambda env
			&ec2rolecreds.EC2RoleProvider{Client: ec2metadata.New(sess)},
		})
	cfg := &aws.Config{
		Region:                        aws.String("ap-southeast-1"),
		Credentials:                   creds,
		CredentialsChainVerboseErrors: aws.Bool(true),
	}
	sess, err = session.NewSession(cfg)
	b, err = s3blob.OpenBucket(ctx, sess, bucket, nil)
	return
}
