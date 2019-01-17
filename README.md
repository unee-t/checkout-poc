Video about it: https://youtu.be/0zFcxszKHHw

Premise: Minimum POC to integrate with **checkout_beta_4**
https://stripe.com/docs/payments/checkout which is not to be confused with the
old [checkout.js](https://stripe.com/docs/checkout) (modal) flow.

# Problem: If user adds a different billing email address

This should be fixed soon according to Stripe.

# Problem: Takes time for the Web hook to acknowledge the user is successfully subscribed

We use a /success end point, and we wait on the Webhook source of truth.
However perhaps we can look at the referer for added confirmation.

# Problem: If a subscription is cancelled, customer is still around

We will remove s3://$bucket/$email containing the subscription ID in the case
the subscription is cancelled. However, the customer will still exist and would
need to be manually cleared up. We adopt this strategy since we might want
cases where is a billing entity (aka a customer) with multiple subscriptions.
