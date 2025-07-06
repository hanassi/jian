
BEGIN {
        IGNORECASE = 1;
        B=0;    A=0;    MAX=100;        LAST=0; P=0
}

function last(N)
{
        if(N>L) return("");
        return(LINE[(L-N)%MAX]);
}

{ LINE[(++L)%MAX]=$0 } # Remember line for later

(tolower($0) ~ tolower(PAT)) {
        if((NR - LAST) > B)     LAST = (NR-B);

        P=A+1

        while(LAST <= NR)
        {
                print last(NR-LAST);
                LAST++;
        }
        next
}

((--P)>0)
