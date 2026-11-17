# Extract only the destination hostname from an HTTP(S) origin or URL.
def hostname:
  strings
  | capture("(?i)\\Ahttps?://(?<host>[a-z0-9.-]+)(?::[0-9]{1,5})?(?:[/?#].*)?\\z")
  | .host | ascii_downcase | sub("\\.$"; "");

def event($destination; $disposition; $directive):
  select($disposition == "enforce" or $disposition == "report")
  | ($destination | hostname) as $host
  | {
      integration: "optimizely_csp",
      csp: {
        destination: $host,
        disposition: $disposition,
        directive: ($directive | strings)
      }
    };

if type == "array" then
  .[] | objects | select(.type == "csp-violation") | .body | objects
  | event(.blockedURL; .disposition; .effectiveDirective)
elif type == "object" then
  ."csp-report" | objects
  | event(."blocked-uri"; .disposition; ."effective-directive")
else empty end
