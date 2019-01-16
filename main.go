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
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/customer"
	"github.com/stripe/stripe-go/sub"
	"github.com/stripe/stripe-go/webhook"
	"github.com/tj/go/http/response"
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
	app.HandleFunc("/cancel", cancel)
	app.HandleFunc("/login", getlogin).Methods("GET")
	app.HandleFunc("/login", postlogin).Methods("POST")

	if err := http.ListenAndServe(addr, app); err != nil {
		log.WithError(err).Fatal("error listening")
	}
}

func cancel(w http.ResponseWriter, r *http.Request) {
	email, err := r.Cookie("email")
	if err != nil || email.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	subID, err := load(email.Value)
	if err != nil {
		log.Errorf("Failed to load customer record using subID: %s", subID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.WithFields(log.Fields{
		"subID": subID,
		"email": email.Value,
	}).Info("cancel")

	c, err := sub2customer(string(subID))
	if err != nil {
		log.Errorf("Failed to load customer email: %s", email.Value)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = delcustomer(c.ID, email.Value)
	http.Redirect(w, r, "/", http.StatusFound)
}

func delcustomer(custID string, email string) (err error) {
	_, err = customer.Del(custID, nil)
	if err != nil {
		log.Errorf("Failed to delete customer ID: %s", custID)
		// Continue to delete customer record from bucket
	}
	err = del(email)
	if err != nil {
		log.Errorf("Failed to delete customer email: %s", email)
		return
	}
	return
}

func index(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	email, err := r.Cookie("email")
	if err != nil || email.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	b, err := setupAWS(ctx, bucket)
	if err != nil {
		log.Errorf("Failed to setup bucket: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userinfo, err := b.ReadAll(ctx, email.Value)
	var status string
	if err != nil {
		log.Warnf("Failed to access user info: %s", email.Value)
	}
	status = string(userinfo)

	views.ExecuteTemplate(w, "index.html", struct {
		Email            string
		SubscriberStatus string
	}{
		Email:            email.Value,
		SubscriberStatus: status,
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

func load(key string) (payload []byte, err error) {
	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		log.Errorf("Failed to setup bucket: %s", err)
		return payload, err
	}

	r, err := b.NewReader(ctx, key, nil)
	if err != nil {
		log.Errorf("Failed to obtain reader: %s", err)
		return payload, err
	}

	payload, err = ioutil.ReadAll(r)
	if err != nil {
		log.Errorf("Failed to read from bucket: %s", err)
		return payload, err
	}
	if err := r.Close(); err != nil {
		log.Errorf("Failed to close: %s", err)
		return payload, err
	}

	log.Infof("Read from to s3://%s/%s = %q", bucket, key, string(payload))

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
	case "checkout_beta.session_succeeded":
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
		// We save the subscription ID, although the customer ID is probably of more import
		err = save(cust.Email, subID)
		if err != nil {
			log.Errorf("Failed to record customer %s as subscribing to %s", cust.Email, subID)
			return
		}
	case "customer.deleted":
		// We need to to remove the earlier saved customer record from the bucket
		id, _ := event.Data.Object["id"].(string)
		email, ok := event.Data.Object["email"].(string)
		if !ok {
			log.Errorf("Failed to retrieve customer email %s", event.ID)
			return
		}
		err = delcustomer(id, email)
		if err != nil {
			log.WithFields(log.Fields{
				"customerID": id,
				"email":      email,
			}).Error("deleting from customer.deleted")
			return
		}
	case "customer.subscription.deleted":
		subID, ok := event.Data.Object["id"].(string)
		if !ok {
			log.Errorf("Failed to retrieve subscription id from %s", event.ID)
			return
		}
		// Will result in ignorable errors if customer is closed simultaneously
		cust, err := sub2customer(subID)
		if err != nil {
			log.Warnf("Failed to retrieve customer email from %s", subID)
			return
		}
		err = delcustomer(cust.ID, cust.Email)
		if err != nil {
			log.WithFields(log.Fields{
				"customerID": cust.ID,
				"email":      cust.Email,
			}).Error("cancel from customer.subscription.deleted")
			return
		}
	default:
		log.Infof("Ignoring: %s", event.Type)
	}
	response.OK(w)
}

func sub2customer(subID string) (c *stripe.Customer, err error) {
	s, err := sub.Get(subID, nil)
	if err != nil {
		log.Errorf("Failed to retrieve subscription id %s", subID)
		return
	}
	log.Infof("Subscription info: %#v", s)
	log.Infof("Customer info from subscription: %#v", s.Customer)
	c, err = customer.Get(s.Customer.ID, nil)
	if err != nil {
		log.Errorf("Failed to retrieve customer id %s", s.Customer.ID)
		return
	}
	log.Infof("Customer info: %#v", c)
	return c, err
}

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
