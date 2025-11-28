inPath= /home/pi/rpi-wol/backend.go
outPath= /opt/rpi-wol/rpi-wol
goBin= /home/pi/go/bin/go


all:
	${goBin} build -o ${outPath} ${inPath}
