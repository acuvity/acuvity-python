# API Types

This folder contains all models that are being used when interacting with the Acuvity API.

For all "normal" interactions this SDK is actually talking to the Acuvity Apex.
So the interaction with the Acuvity API is minimal.
In this SDK we are interacting with the Acuvity API for one simple reason: to query for the Apex information from the token.
The Apex URL can still be overridden, although that should not be necessary in most cases.
The only necessary piece of information for any interaction is the token: we deduce the API URL from the token, and query that API endpoint for the Apex information.

We reuse the same base models from the apex generated types here for simplicity.
However, as compared to the apex types, these types here are not auto-generated.
Make changes in the files here if you need them.
