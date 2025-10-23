# Build map: alg -> { oxitoken, jsonwebtoken }
  (reduce (inputs
    | select(.reason=="benchmark-complete")
    | select(.id | contains("_openssl") | not)
    | {alg: (.id|split("/")[0]),
       impl: (.id|split("/")[1]|sub("^oxitoken_aws_lc$";"oxitoken")),
       val: .median.estimate}
  ) as $r
  ({}; .[$r.alg] = (.[$r.alg] // {}) | .[$r.alg][$r.impl] = $r.val)) as $t

  # Emit Markdown with unit-aware formatting (≥1000 ns -> µs) and % faster
  | ([
      "# Validation Performance",
      "",
      "| Algorithm | oxitoken | jsonwebtoken | % faster |",
      "|---|---:|---:|---:|"
    ]
    + ($t
        | keys | sort
        | map(
            . as $alg
            | ($t[$alg].oxitoken // null) as $o
            | ($t[$alg].jsonwebtoken // null) as $j

            # value formatters (ns -> ns/µs)
            | ($o
               | if .==null then "" 
                 else if . >= 1000
                   then ((((. / 1000) * 100) | round) / 100 | tostring) + " µs"
                   else (((. * 100) | round) / 100 | tostring) + " ns"
                 end
               end) as $o_str
            | ($j
               | if .==null then "" 
                 else if . >= 1000
                   then ((((. / 1000) * 100) | round) / 100 | tostring) + " µs"
                   else (((. * 100) | round) / 100 | tostring) + " ns"
                 end
               end) as $j_str

            # percent faster: ((j - o)/j) * 100
            | (if ($o!=null and $j!=null and $j>0)
                 then (((($j - $o) / $j) * 10000 | round) / 100)
                 else null
               end) as $p
            | (if $p==null then "" else ($p | tostring) + " %" end) as $p_str

            # one Markdown row
            | "| " + $alg
              + " | " + $o_str
              + " | " + $j_str
              + " | " + $p_str
          )
      )
    )[]
