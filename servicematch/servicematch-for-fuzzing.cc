#include "nbase.h"
#include "nmap.h"
#include "nmap_error.h"
#include "service_scan.h"
#include "utils.h"


#define PERSIST_MAX 1000

unsigned int persist_cnt;


/* Main entry point. */

int main(int argc, char** argv) {

  AllProbes *AP = new AllProbes();
  const char *probefile = "../nmap-service-probes";
  parse_nmap_service_probe_file(AP, (char *)probefile);

  const char *probename = "GenericLines";
  const int proto = IPPROTO_TCP;
  ServiceProbe *SP = AP->getProbeByName(probename, proto);
  if (!SP)
    fatal("Unable to find probe named %s in given probe file.", probename);

  char resptext[2048];

  FILE *fpfile;
  int resptextlen;
  bool do_close = false;


try_again:

  if (do_close)
    fclose(fpfile);
  do_close = true;
  fpfile = fopen(argv[1], "r");
  if (!fpfile)
    fatal("No fpfile given.");

  resptextlen = fread(resptext, 1, 2048, fpfile);

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

  if (getenv("AFL_PERSISTENT") && persist_cnt++ < PERSIST_MAX) {

    raise(SIGSTOP);
    goto try_again;

  }

  /* If AFL_PERSISTENT not set or PERSIST_MAX exceeded, exit normally. */

  return 0;

}
