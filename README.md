# acuvity-python

This is a simple python package to use the Acuvity detection APIs.

## TODOs

* [x] discovery through well-known API instead of orgsettings
* [x] ensure apex CA is being accounted for automatically in the used HTTP client when well-known API is used
* [x] response must be parsed as json or msgpack depending on the content-type header, not based on what we requested
* [x] retries with exponential backoff plus jitter
* [x] move to request object
* [x] add a "raw" validate function call, or make it part of functions as single object as input
* [x] add second validate function
* [ ] complete README with examples, ensure PyPI has all important data that we need
* [ ] move types to spec in apex
* [ ] generate python and javascript models from specs, and release them as their own module
* [ ] write some basic tests somehow
* [ ] async client
