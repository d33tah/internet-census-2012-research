#include "nbase.h"
#include "nmap.h"
#include "nmap_error.h"
#include "service_scan.h"
#include "utils.h"

#include <ctype.h>

int main(int argc, char *argv[]) {

  AllProbes *AP = new AllProbes();
  const char *probefile = "../nmap-service-probes";
  parse_nmap_service_probe_file(AP, (char *)probefile);

  const char *probename = "GenericLines";
  const int proto = IPPROTO_TCP;
  ServiceProbe *SP = AP->getProbeByName(probename, proto);
  if (!SP)
    fatal("Unable to find probe named %s in given probe file.", probename);

  char resptext[2048];
  FILE *fpfile = fopen(argv[1], "r");
  if (!fpfile)
    fatal("No fpfile given.");
  const int resptextlen = fread(resptext, 1, 2048, fpfile);

  int fallbackDepth, n;
  for (fallbackDepth = 0; SP->fallbacks[fallbackDepth] != NULL;
      fallbackDepth++) {
    const struct MatchDetails *MD;
    for (n = 0; (MD = SP->fallbacks[fallbackDepth]->testMatch(
            (const u8 *)resptext, resptextlen, n)) != NULL;
        n++) {
      if (MD->serviceName != NULL) {
        printf("Found\n");
      }
    }
    for (n = 0; (MD = SP->fallbacks[fallbackDepth]->testMatch(
            (const u8 *)resptext, resptextlen, n)) != NULL;
        n++) {
      if (MD->serviceName != NULL) {
        printf("Found\n");
      }
    }
  }
  return 0;
}
