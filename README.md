Video about it: https://youtu.be/0zFcxszKHHw

Premise: Minimum POC to integrate with BETA
https://stripe.com/docs/payments/checkout which is not to be confused with the
old [checkout.js](https://stripe.com/docs/checkout) (modal) flow.

# Problem 1: If user adds a different billing email address

Stripe's answer:

	If you want your customers to be able to enter email address in advance, you'd
	need to use Custom Checkout here:
	https://stripe.com/docs/checkout#integration-custom.

# Problem 2: It can take time for user to become subscribed

Ask user to refresh after paying?

Waste time on a "success" / thank you page ?

# Problem 3: customer.subscription.created doesn't exist yet on BETA checkout

Workaround use checkout_beta.session_succeeded

# Problem 4: customer.subscription.deleted won't work if customer is closed

Workaround, add some logic to handle "customer.deleted" and delete customer
record on s3://$bucket/$email.
