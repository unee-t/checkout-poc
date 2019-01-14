package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
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
}

func main() {
	addr := ":" + os.Getenv("PORT")
	app := mux.NewRouter()
	app.HandleFunc("/", index)
	app.HandleFunc("/logout", deletecookie)
	app.HandleFunc("/hook", hook)
	app.HandleFunc("/login", getlogin).Methods("GET")
	app.HandleFunc("/login", postlogin).Methods("POST")

	if err := http.ListenAndServe(addr, app); err != nil {
		log.WithError(err).Fatal("error listening")
	}
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
	log.Infof("userinfo: %+v", userinfo)

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

func dump(key string, payload []byte) (err error) {

	ctx := context.Background()
	b, err := setupAWS(ctx, bucket)
	if err != nil {
		log.Errorf("Failed to setup bucket: %s", err)
		return err
	}

	hookout, err := b.NewWriter(ctx, key, nil)
	if err != nil {
		log.Fatalf("Failed to obtain writer: %s", err)
		return err
	}

	_, err = hookout.Write(payload)
	if err != nil {
		log.Fatalf("Failed to write to bucket: %s", err)
		return err
	}
	if err := hookout.Close(); err != nil {
		log.Fatalf("Failed to close: %s", err)
		return err
	}

	log.Infof("Wrote out to s3://%s/%s", bucket, key)

	return nil

}

func hook(w http.ResponseWriter, r *http.Request) {

	buf := &bytes.Buffer{}
	tee := io.TeeReader(r.Body, buf)

	body, err := ioutil.ReadAll(tee)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), os.Getenv("WH_SIGNING_SECRET"))

	if err != nil {
		log.Fatalf("Failed to verify signature: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Infof("Received signed event: %#v", event)

	payload, err := httputil.DumpRequest(r, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	t := time.Now()
	key := fmt.Sprintf("hooks/%s/%d-%s.txt", t.Format("2006-01-02"), t.Unix(), event.Type)

	err = dump(key, payload)
	if err != nil {
		log.Fatalf("Failed to write to bucket: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response.OK(w)
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
