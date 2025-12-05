inPath= ./backend.go
outPath= /opt/rpi-wol/rpi-wol
stdDirectory=/opt/rpi-wol/

all:
	mkdir -p ${stdDirectory} && mkdir -p ${stdDirectory}.ssh 
	go build -gcflags "all=-N -l" -o ${outPath} ${inPath}
