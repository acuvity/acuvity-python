# acuvity-python

This is a simple python package to use the Acuvity detection APIs.

## TODOs

* [ ] retries with exponential backoff plus jitter
* [ ] response must be parsed as json or msgpack depending on the content-type header, not based on what we requested
* [ ] discovery through well-known API instead of orgsettings
* [ ] ensure apex CA is being accounted for automatically in the used HTTP client when well-known API is used
* [ ] move to request object
* [ ] add second validate function
* [ ] add a "raw" validate function call, or make it part of functions as single object as input
* [ ] move types to spec in apex
* [ ] generate python and javascript models from specs, and release them as their own module
* [ ] write some basic tests somehow
* [ ] async client
