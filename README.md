# Rustbucket Registry
Honeypots are fun - but they're only useful at scale. And managing a bunch of honeypots on your own is a freakin' pain.
And it's also risky. You're exposing a bunch of potentially vulnerable systems to the internet. Oh, and if you forget 
about four or five of them, enjoy your Cloud bill!

Rustbucket Registry allows you to register and manage your Rustbucket instances. Every time a Rustbucket is stood up,
it'll try to register itself with your registry. All you have to do is approve it. And if you ever want to take it down,
your Rustbucket will try to deregister itself.

Easy peasy.