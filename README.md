# Proof of concept. Do not use.

## Usage

The idea is to enable convenient use of the AWS API demanding that the user,
has recently used MFA, while also avoiding having to type the MFA token in
every time.

To complicate matters further, you may also want to assume a role.

So, in our Amazon account we have a few things:

1. You have a user, with some credentials which are not allowed to do anything
   by default.
2. You give the user the the power to do things, but only if they have MFA auth.
3. You allow the user to assume a role, but only if they have young MFA auth.


Then you can run this:

```
AWS_MFA_SERIAL=GAHP01234567 AWS_ASSUME_ROLE_ARN=aws:arn:.... AWS_ASSUME_ROLE_SESSION_NAME=peter \
aws-creds aws ec2 describe-instances
```

This will prompt you for MFA. But only once in a while.

Behind the scenes it caches the credentials and automatically refreshes the
role every time for as long as it is allowed.

The net effect is that you authenticate with MFA once, and now we can specify
for how long those credentials are valid, for longer than one hour.

Under the covers, we are only allowed to use the credentials given by an
`sts assume-role` for an hour before they become invalid. For
`sts get-session-token` this is a different story, these can be valid for a
specified length of time (days). Furthermore, if the `assume-role` demands MFA,
then the MFA token supplied at time of `get-session-token` is sufficient.
