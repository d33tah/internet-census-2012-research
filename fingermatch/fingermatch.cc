/***************************************************************************
 * fingermatch.cc -- A relatively simple utility for determining whether a *
 * given Nmap fingerprint matches (or comes close to matching) any of the  *
 * fingerprints in a collection such as the nmap-os-db file that ships     *
 * with Nmap.                                                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id: fingermatch.cc 4113 2006-11-01 23:31:18Z fyodor $ */


#include "nbase.h"
#include "nmap.h"
#include "nmap_error.h"
#include "osscan.h"
#include "fingerlib.h"

#include <getopt.h>

void set_program_name(const char *name);

#define FINGERMATCH_GUESS_THRESHOLD 0.80 /* How low we will still show guesses for */
/* The maximum number of guesses to display if there are no perfect matches. */
#define MAX_GUESSES 10
/* The maximum number of guesses to display if there is at least one perfect
   match. */
#define MAX_ADDITIONAL_GUESSES 10

void usage(char *argv0) {
  printf(
"Usage: %s [options]\n"
"\n"
"The fingerprint data in Nmap format will be read from the standard input.\n"
"  -f, --fp-file <filename>   Use the specified Nmap fingerprint database\n"
"  -h, --help                 Display this help screen\n"
"  -g, --guess-threshold <n>  Set the guess threshold to n percent (0 < n < 100)\n"
"  -q  --quiet                Display one line of output per fingerprint\n"
, argv0);
  exit(0);
}

static void print_match(const FingerPrintResultsIPv4& FPR, unsigned int i, int quiet_flag);


int main(int argc, char *argv[]) {
  char *fingerfile = NULL;
  FingerPrintDB *reference_FPs = NULL;
  FingerPrint *testFP;
  struct FingerPrintResultsIPv4 FPR;
  char fprint[8192];
  int i, rc, n, c, option_index, guess_threshold_percent = -1;
  int quiet_flag = 0;
  double guess_threshold;

  set_program_name(argv[0]);

  while (1) {
    static struct option long_options[] = {
      {"fp-file",           required_argument,  0, 'f'},
      {"guess-threshold",   required_argument,  0, 'g'},
      {"help",              no_argument,        0, 'h'},
      {"quiet",             no_argument,        0, 'q'},
      {0, 0, 0, 0}
    };
    c = getopt_long(argc, argv, "f:g:hq", long_options, &option_index);
    /* Detect the end of the options. */
    if (c == -1)
      break;
    switch (c) {
      case 'f':
        fingerfile = optarg;
        break;
      case 'g':
        if (guess_threshold_percent != -1)
          error("[WARN] guess threshold already specified!");
        guess_threshold_percent = atoi(optarg);
        if (guess_threshold_percent <= 0 || guess_threshold_percent > 100)
          fatal("Invalid guess threshold. Please enter a number between 1 and 100.");
        break;
      case 'h':
        usage(argv[0]);
        break;
      case 'q':
        if (quiet_flag)
          error("[WARN] --quiet already specified!");
        quiet_flag = 1;
        break;
      case '?':
        /* getopt_long already printed an error message. */
        fatal("Try `--help' for more information, usage options and help.");
        break;
      default:
        fatal("FIXME: hit an option specified in getopt_long but not implemented.");
    }
  }

  if (guess_threshold_percent == -1)
    guess_threshold_percent = 100;
  guess_threshold = guess_threshold_percent / 100.0;

  if (fingerfile == NULL) {
    error("[ERROR] No fingerprint database specified!");
    fatal("Try `--help' for more information, usage options and help.");
  }

  /* First we read in the fingerprint file provided on the command line */
  reference_FPs = parse_fingerprint_file(fingerfile);
  if (reference_FPs == NULL)
    fatal("Could not open or parse Fingerprint file given on the command line: %s", fingerfile);

  for (;;) {

    FingerPrint *testFP;
    struct FingerPrintResultsIPv4 FPR;

    if (!quiet_flag) {
      /* Now we read in the user-provided fingerprint */
      printf("Enter the fingerprint you would like to match, followed by a blank single-dot line:\n");
    }

    if (feof(stdin))
      break;

    if (readFP(stdin, fprint, sizeof(fprint), quiet_flag) == -1)
      fatal("[ERROR] Failed to read in supposed fingerprint from stdin\n");

    testFP = parse_single_fingerprint(fprint);
    if (!testFP) fatal("Sorry -- failed to parse the so-called fingerprint you entered");

    if ((rc = remove_duplicate_tests(testFP))) {
      error("[WARN] Adjusted fingerprint due to %d duplicated tests (we only look at the one with the most attributes).\n", rc);
    }

    /* Now we find the matches! */
    match_fingerprint(testFP, &FPR, reference_FPs, FINGERMATCH_GUESS_THRESHOLD);

    switch(FPR.overall_results) {
    case OSSCAN_NOMATCHES:
      if (quiet_flag)
          printf("No matches\n");
      else
          printf("**NO MATCHES** found for the entered fingerprint in %s\n", fingerfile);
      break;
    case OSSCAN_TOOMANYMATCHES:
    case OSSCAN_SUCCESS:
      if (quiet_flag) {
        if (FPR.num_perfect_matches > 0)
          print_match(FPR, 0, quiet_flag);
        else
          printf("No matches\n");
        break;
      }
      if (FPR.num_perfect_matches > 0) {
        printf("Found **%d PERFECT MATCHES** for entered fingerprint in %s:\n", FPR.num_perfect_matches, fingerfile);
        printf("Accu Line# OS (classification)\n");
        for(i=0; i < FPR.num_matches && FPR.accuracy[i] == 1; i++)
          print_match(FPR, i, quiet_flag);
        printf("**ADDITIONAL GUESSES** for entered fingerprint in %s:\n", fingerfile);
        printf("Accu Line# OS (classification)\n");
        n = 0;
        for(i=0; i < 10 && i < FPR.num_matches && n < MAX_ADDITIONAL_GUESSES; i++) {
          if (FPR.accuracy[i] < 1) {
            print_match(FPR, i, quiet_flag);
            n++;
          }
        }
      } else {
        printf("No perfect matches found, **GUESSES AVAILABLE** for entered fingerprint in %s:\n", fingerfile);
        printf("Accu Line# OS (classification)\n");
        for(i=0; i < MAX_GUESSES && i < FPR.num_matches; i++)
          print_match(FPR, i, quiet_flag);
      }
      printf("\n");
      break;
    default:
      fatal("Bogus error.");
      break;
    }

    fflush(stdout);

  }

  return 0;
}

static void print_match(const FingerPrintResultsIPv4& FPR, unsigned int i, int quiet_flag) {
  struct OS_Classification& OS_class = FPR.matches[i]->OS_class[0];

  printf("%3.f%% %5d %s (", floor(FPR.accuracy[i] * 100), FPR.matches[i]->line, FPR.matches[i]->OS_name);
  if (OS_class.OS_Vendor != NULL)
    printf("%s ", OS_class.OS_Vendor);
  printf("|");
  if (OS_class.OS_Family != NULL)
    printf(" %s ", OS_class.OS_Family);
  printf("|");
  if (OS_class.OS_Generation != NULL)
    printf(" %s ", OS_class.OS_Generation);
  printf("|");
  if (OS_class.Device_Type != NULL)
    printf(" %s", OS_class.Device_Type);
  printf(")\n");
}
