# Reads the report `dns_blocker --status` writes. Source it, do not run it.
#
# One parser, shared by the live checks and the soak sampler. The report is
# written by status.c and read here by two callers, so a second copy of these
# two functions is a format that can drift against itself.

# One line of a report, without its leading key
StatusLine() # <report> <key>
{
    printf '%s\n' "$1" | awk -v key="$2" '
        $1 == key { $1 = ""; sub(/^ +/, ""); print; exit }'
}

# The number a label carries. The report writes both orders, `reused 12` and
# `12 bytes`, so each pair is read from either side. Commas belong to the
# report, so a word is stripped to its own alphabet before it is compared
StatusCount() # <line> <label>
{
    printf '%s\n' "$1" | awk -v want="$2" '
        function word(s) { gsub(/[^a-z0-9]/, "", s); return s }
        {
            # Label first, because `local 0, forwarded 9` reads as a value
            # before `forwarded` as well, and that reading is the wrong one
            for(i = 1; i < NF; i++)
            {
                if(word($i) == want && word($(i + 1)) ~ /^[0-9]+$/)
                {
                    print word($(i + 1))
                    exit
                }
            }

            for(i = 1; i < NF; i++)
            {
                if(word($(i + 1)) == want && word($i) ~ /^[0-9]+$/)
                {
                    print word($i)
                    exit
                }
            }
        }'
}
