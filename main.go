package main

import (
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/apex/log"
	jsonloghandler "github.com/apex/log/handlers/json"
	"github.com/apex/log/handlers/text"
	"github.com/gorilla/mux"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/customer"
	"github.com/stripe/stripe-go/sub"
	"github.com/stripe/stripe-go/webhook"
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
	app.HandleFunc("/sorry", sorry)
	app.HandleFunc("/success", success)
	app.HandleFunc("/cancel", cancel)
	app.HandleFunc("/login", getlogin).Methods("GET")
	app.HandleFunc("/login", postlogin).Methods("POST")

	if err := http.ListenAndServe(addr, app); err != nil {
		log.WithError(err).Fatal("error listening")
	}
}

func accessLog(r *http.Request) *log.Entry {
	l := log.WithFields(log.Fields{
		"method":     r.Method,
		"requestURI": r.RequestURI,
		"referer":    r.Referer(),
		"ua":         r.UserAgent(),
	})
	return l
}

// User waits here until the Web hook comes in updating the s3://$bucket/$email file
func success(w http.ResponseWriter, r *http.Request) {
	log := accessLog(r)
	log.Info("success")
	views.ExecuteTemplate(w, "success.html", nil)
}

// User waits here until the Web hook comes in updating the s3://$bucket/$email file
func sorry(w http.ResponseWriter, r *http.Request) {
	log := accessLog(r)
	log.Info("sorry")
	views.ExecuteTemplate(w, "sorry.html", nil)
}

func cancel(w http.ResponseWriter, r *http.Request) {
	// Assuming the customer has only one associated active subscription,
	// we delete the customer which automatically deletes the sub & payment src

	// Identify
	email, err := r.Cookie("email")
	if err != nil || email.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Pull up our user record
	subID, err := load(email.Value)
	if err != nil {
		log.WithField("email", email.Value).Errorf("Failed to load subID")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the stripe Customer ID
	cust, err := sub2customer(subID)
	if err != nil {
		log.WithError(err).Error("failed to retrieve customer")
		return
	}

	log := log.WithFields(log.Fields{
		"subscriberID": subID,
		"customerID":   cust.ID,
	})

	// Assuming customer is not a company type, with a varying quantity of subscriptions
	_, err = customer.Del(cust.ID, &stripe.CustomerParams{})
	if err != nil {
		log.WithError(err).Error("failed to delete customer")
		return
	}

	// We don't redirect immediately to the user status page, because the user record actually only gets updated once
	// Stripe sends us the Webhook, which can take a second or two
	http.Redirect(w, r, "/sorry", http.StatusFound)
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

func hook(w http.ResponseWriter, r *http.Request) {

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.WithError(err).Error("failed to parse body")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), os.Getenv("WH_SIGNING_SECRET"))
	if err != nil {
		log.WithError(err).Error("failed to verify signature")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Debugf("Received signed event: %#v", event)

	switch event.Type {
	case "customer.subscription.created":
		log.Infof("WOW time to replace checkout_beta.session_succeeded?? %s", event.Type)
	case "customer.deleted":
		log.Info("customer.deleted")
		email, ok := event.Data.Object["email"].(string)
		if !ok {
			log.WithError(err).WithField("event", event.ID).Error("failed to retrieve email id")
			return
		}
		// Remove the state that tells us our user is paying
		err = del(email)
		if err != nil {
			log.WithError(err).Errorf("failed to remove s3://%s/%s", bucket, email)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.WithField("email", email).Info("removed S3 user record")
	case "checkout_beta.session_succeeded":
		log.Infof("%s", event.Type)
		subID, ok := event.Data.Object["subscription"].(string)
		if !ok {
			log.WithError(err).WithField("event", event.ID).Error("failed to retrieve subscription id")
			return
		}
		cust, err := sub2customer(subID)
		if err != nil {
			log.WithError(err).WithField("subID", subID).Error("failed to retrieve customer email")
			return
		}
		// We save the subscription ID
		err = save(cust.Email, subID)
		if err != nil {
			log.WithError(err).Errorf("failed to record customer %s as subscribing to %s", cust.Email, subID)
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
		log.WithError(err).Errorf("failed to retrieve subscription id %s", subID)
		return
	}
	log.Debugf("Subscription info: %#v", s)
	log.Debugf("Customer info from subscription: %#v", s.Customer)
	c, err = customer.Get(s.Customer.ID, nil)
	if err != nil {
		log.WithError(err).Errorf("failed to retrieve customer id %s", s.Customer.ID)
		return
	}
	log.Debugf("Customer info: %#v", c)
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
