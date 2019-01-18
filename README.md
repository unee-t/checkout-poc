Video about it: https://youtu.be/0zFcxszKHHw

Premise: Minimum POC to integrate with **checkout_beta_4**
https://stripe.com/docs/payments/checkout which is not to be confused with the
old [checkout.js](https://stripe.com/docs/checkout) (modal) flow.

# Problem: If user adds a different billing email address

This should be fixed soon according to Stripe.

# Problem: Takes time for the Web hook to acknowledge the user is successfully subscribed

We use a /success end point for subscribing and a /sorry end point for cancellation.
We wait on the Webhook source of truth.

# Problem: When a customer becomes a company

If the 1 customer to 1 subscription mapping changes, i.e. a customer is a
business with several users in its account, we need to move to:
https://stripe.com/docs/billing/subscriptions/quantities or
https://stripe.com/docs/billing/subscriptions/metered-billing

This effectively complicates our logic since we need to **report** to Stripe
how much the business utilises our service. i.e. we can't rely on Stripe Web
hooks to update our user table on events, whether a user is subscribed or not.
