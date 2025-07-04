#!/usr/bin/awk -f
# ctx.awk: PAT 문자열 전후 줄(Before/After)을 출력하는 스크립트

BEGIN {
    B = (ENVIRON["B"]  ? ENVIRON["B"]  : 0) + 0
    A = (ENVIRON["A"]  ? ENVIRON["A"]  : 0) + 0
    PAT = ENVIRON["PAT"]
    if (PAT == "") {
        print "Usage: PAT=pattern B=num A=num awk -f ctx.awk file" > "/dev/stderr"
        exit 1
    }
}

{
    buffer[NR] = $0
    if (index($0, PAT) > 0) {
        start = NR - B
        end   = NR + A
        for (i = (start>1?start:1); i <= end; i++) {
            if (i in buffer) print buffer[i]
        }
    }
}
