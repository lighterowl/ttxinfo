# Teletext Analyzer

This is a simple application that is meant to read a MPEG-TS (H.222) file, demux
one of the elementary streams identified by its PID, assemble PES packets which
form that elementary stream, treat that elementary stream as a DVB Teletext
stream and display information about teletext packets from their headers.

As far as I'm aware, this is of no real use and can only be used when debugging
some weird transport streams that contain teletext. It can also serve as a very
basic example on how to write a MPEG-TS demuxer or a PES packetizer.
