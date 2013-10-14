/***************************************************************************
 * fingerlib.cc/.h -- Some misc. functions related to fingerprint parsing  *
 * and the like to be used by integration-related programs such as         *
 * fingerfix, fingermatch, and fingerdiff                                  *
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


#include "nbase.h"
#include "nmap.h"
#include "nmap_error.h"
#include "fingerlib.h"
#include "osscan.h"
#include "MACLookup.h"

#include <errno.h>

#define HIGHEST_GOOD_DISTANCE 5

static bool check_SCAN(const FingerTest *ft) {
  std::vector<struct AVal>::const_iterator av;
  u8 macprefix[3];
  unsigned int i;
  bool seen_G = false;
  bool found_error = false;

  assert(strcmp(ft->name, "SCAN") == 0);

  for (av = ft->results.begin(); av != ft->results.end(); av++) {
    if (strcmp(av->attribute, "DS") == 0) {
      long distance;
      char *tail;
      errno = 0;
      distance = strtol(av->value, &tail, 10);
      if (errno != 0 || *tail != '\0') {
        printf("[WARN] Unparseable value for %s.%s: %s\n",
          ft->name, av->attribute, av->value);
        found_error = true;
      } else if (distance > HIGHEST_GOOD_DISTANCE) {
        printf("[WARN] Network distance (%ld hops) is greater than %d\n",
          distance, HIGHEST_GOOD_DISTANCE);
      }
    } else if (strcmp(av->attribute, "G") == 0) {
      seen_G = true;
      if (strcmp(av->value, "Y") != 0) {
        printf("[WARN] Fingerprint classified NOT SUITABLE FOR SUBMISSION\n");
        found_error = true;
      }
    } else if (strcmp(av->attribute, "M") == 0) {
      for(i = 0; i < 6; i++) {
        if(av->value[i] == '\0' || !isxdigit(av->value[i])) {
          printf("[WARN] Invalid value (%s) occurs in SCAN.M\n", av->value);
          found_error = true;
          break;
        }
      }
      if (i == 6) {
        i = strtol(av->value, NULL, 16);
        macprefix[0] = i >> 16;
        macprefix[1] = (i >> 8) & 0xFF;
        macprefix[2] = i & 0xFF;
        printf("[INFO] Vendor Info: %s\n", MACPrefix2Corp(macprefix));
      }
    }
  }
  if (!seen_G) {
    printf("[WARN] Attribute G is missing in SCAN line\n");
    found_error = true;
  }

  return found_error;
}

static bool check_IE(const FingerTest *ft) {
  std::vector<struct AVal>::const_iterator av;
  bool found_error = false;

  assert(strcmp(ft->name, "IE") == 0);

  for (av = ft->results.begin(); av != ft->results.end(); av++) {
    if (strcmp(ft->name, "IE") == 0 && strcmp(av->attribute, "R") == 0
      && strcmp(av->value, "Y") != 0) {
      printf("[WARN] Target failed to respond to ICMP ping\n");
      found_error = true;
    }
  }

  return found_error;
}

static bool check_T_attr(const FingerPrint *fp) {
  /* These are the tests that contain a "T" attribute. */
  const char *T_TESTS[] = {
    "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE"
  };
  std::vector<FingerTest>::const_iterator ft;
  std::vector<struct AVal>::const_iterator av;
  long ttl, max_ttl;
  const char *value;
  char *tail;
  unsigned int i, count;

  count = 0;
  for (ft = fp->tests.begin(); ft != fp->tests.end(); ft++) {
    for (i = 0; i < sizeof(T_TESTS) / sizeof(*T_TESTS); i++) {
      if (strcmp(ft->name, T_TESTS[i]) != 0)
        continue;
      for (av = ft->results.begin(); av != ft->results.end(); av++) {
        if (strcmp(av->attribute, "T") == 0) {
          max_ttl = -1;
          value = av->value;
          do {
            errno = 0;
            ttl = strtol(value, &tail, 16);
            if (*tail == '-')
              ttl = strtol(tail + 1, &tail, 16);
            if (ttl > max_ttl)
              max_ttl = ttl;
            if (*tail == '|')
              value = tail + 1;
          } while (errno == 0 && *tail == '|');
          if (errno != 0 || *tail != '\0') {
            printf("[WARN] Unparseable value for %s.%s: %s\n",
              ft->name, av->attribute, av->value);
            return true;
          } else if (max_ttl > 0xFF) {
            if (count == 0) {
              printf(
"[WARN] This fingerprint contains T attributes whose value is greater than 0xFF.\n"
"       Some operating systems (particularly Cisco IOS) seem to cause this to\n"
"       happen often enough that their reference fingerprints should include such\n"
"       large TTLs. However, this can also be caused by strange network\n"
"       conditions unrelated to the operating system, so be careful.\n"
"       This is true for these tests: ");
            } else {
              printf(", ");
            }
            printf("%s.%s (%s)", ft->name, av->attribute, av->value);
            count++;
          }
        }
      }
    }
  }

  if (count > 0)
    printf("\n");

  return count > 0;
}

static bool check_empty_values(const FingerTest *ft) {
  /* Some response tests are not allowed to have an empty value (something like
     "%RID=%"). If a database fingerprint or submission has an empty value for
     any of these tests, something is wrong. Note that a test being present
     without a value is different from a test being absent altogether. */
  const struct {
    const char *name;
    const char *attribute;
  } VALUE_REQUIRED[] = {
    { "SEQ", "TI" }, { "SEQ", "II" }, { "SEQ", "SS" }, { "U1", "RID" }
  };
  std::vector<struct AVal>::const_iterator av;
  bool found_error = false;
  unsigned int i;

  for (i = 0; i < sizeof(VALUE_REQUIRED) / sizeof(*VALUE_REQUIRED); i++) {
    if (strcmp(ft->name, VALUE_REQUIRED[i].name) != 0)
      continue;
    for (av = ft->results.begin(); av != ft->results.end(); av++) {
      if (strcmp(av->attribute, VALUE_REQUIRED[i].attribute) == 0
        && *av->value == '\0') {
        printf("[WARN] Illegal empty value for the response test %s.%s\n",
          VALUE_REQUIRED[i].name, VALUE_REQUIRED[i].attribute);
        found_error = true;
      }
    }
  }

  return found_error;
}

/* Checks a fingerprint and prints warnings to the screen if anything is
   strange. */
static bool checkFP(const FingerPrint *fp) {
  /* This data structure just keeps track of which tests have been seen. */
  struct {
    const char *name;
    bool seen;
  } tests_seen[] = {
    { "SEQ", false }, { "OPS", false }, { "WIN", false }, { "ECN", false },
    { "T1", false }, { "T2", false }, { "T3", false }, { "T4", false },
    { "T5", false }, { "T6", false }, { "T7", false }, { "U1", false },
    { "IE", false }
  };
  std::vector<FingerTest>::const_iterator ft;
  std::vector<struct AVal>::const_iterator av;
  bool found_error = false;
  unsigned int i;

  found_error |= check_T_attr(fp);

  for (ft = fp->tests.begin(); ft != fp->tests.end(); ft++) {
    for (i = 0; i < sizeof(tests_seen) / sizeof(*tests_seen); i++) {
      if (strcmp(ft->name, tests_seen[i].name) == 0) {
        tests_seen[i].seen = true;
        break;
      }
    }

    if (strcmp(ft->name, "SCAN") == 0)
      found_error |= check_SCAN(&*ft);
    else if (strcmp(ft->name, "IE") == 0)
      found_error |= check_IE(&*ft);

    found_error |= check_empty_values(&*ft);
  }

  for (i = 0; i < sizeof(tests_seen) / sizeof(*tests_seen); i++) {
    if (!tests_seen[i].seen) {
      printf("[WARN] %s line is missing\n", tests_seen[i].name);
      found_error = true;
    }
  }

  return found_error;
}

/* Reads a fingerprint in from the filep file descriptor.  The FP may
   be in wrapped or unwrapped format.  Wrapped prints are unrapped
   before being returned in FP.  Returns -1 or exits if it fails. */
int readFP(FILE *filep, char *FP, int FPsz ) {
  char line[2048];
  char extraline[4096];
  int linelen = 0;
  int lineno = 0;
  char *p, *q;
  char *dst = FP;
  char tmp[16];
  int i;
  bool isInWrappedFP = false; // whether we are currently reading in a
                              // wrapped fingerprint

  if(FPsz < 50) return -1;
  FP[0] = '\0';
  extraline[0] = '\0';

  while(*extraline || fgets(line, sizeof(line), filep)) {
    /* The extraline stuff is a hack to fix a very common
       cut-and-paste problem where two lines are concatenated
       together */
        if (*extraline) {
          Strncpy(line, extraline, sizeof(line));
          extraline[0] = '\0';
        }
        if (strlen(line) >= FP_RESULT_WRAP_LINE_LEN + 4) {
          if (strncmp(line + FP_RESULT_WRAP_LINE_LEN + 1, "OS:", 3) == 0) {
            Strncpy(extraline, line + FP_RESULT_WRAP_LINE_LEN + 1, sizeof(extraline));
            line[FP_RESULT_WRAP_LINE_LEN + 1] = '\n';
            line[FP_RESULT_WRAP_LINE_LEN + 2] = '\0';
          }
        }
        lineno++;
        linelen = strlen(line);
        p = line;
        if (dst > FP && (*p == '\n' || *p == '.')) {
          // end of input
          *dst = '\0';

          if(isInWrappedFP)
            // We have just completed reading in a wrapped fp.
            isInWrappedFP = false;
          break;
        }
        while(*p && isspace(*p)) p++;
        if (*p == '#')
          continue; // skip the comment line

        if (dst - FP + linelen >= FPsz - 5)
          fatal("[ERRO] Overflow!\n");

        if(strncmp(p, "OS:", 3) == 0) {
          // the line is start with "OS:"
          if(!isInWrappedFP) {
                // just enter a wrapped fp area
                oneFP = dst;
                isInWrappedFP = true;
          }
          p += 3;
          while(*p != '\r' && *p != '\n') {
            *dst++ = toupper(*p);
            if(*p == ')') *dst++ = '\n';
            p++;
          }
          continue;
        }

        // this line is not start with "OS:"
        if(isInWrappedFP) {
          // We have just completed reading in a wrapped fp.
          *dst = '\0';
          isInWrappedFP = false;
        }

        q = p; i = 0;
        while(q && *q && i<12)
          tmp[i++] = toupper(*q++);
        tmp[i] = '\0';
        if(strncmp(tmp, "FINGERPRINT", 11) == 0) {
          q = p + 11;
          while(*q && isspace(*q)) q++;
          if (*q) { // this fingeprint line is not empty
                strncpy(dst, "Fingerprint", 11);
                dst += 11;
                p += 11;
                while(*p) *dst++ = *p++;
          }
          continue;
        } else if(strncmp(tmp, "MATCHPOINTS", 11) == 0) {
          q = p + 11;
          while(*q && isspace(*q)) q++;
          if (*q) { // this matchpoints line is not empty
                strncpy(dst, "Fingerprint", 11);
                dst += 11;
                p += 11;
                while(*p) *dst++ = *p++;
          }
          continue;
        } else if(strncmp(tmp, "CLASS", 5) == 0) {
          q = p + 5;
          while(*q && isspace(*q)) q++;
          if (*q) {// this class line is not empty
                strncpy(dst, "Class", 5);
                dst += 5;
                p += 5;
                while(*p) *dst++ = *p++;
          }
          continue;
        } else if(strchr(p, '(')) {
          while(*p) *dst++ = toupper(*p++);
        } else {
          printf("[WARN] Skip bogus line: %s\n", p);
          continue;
        }
  }

  /* Parse the fingerprint so we can check it and print warnings. Note that we
     return a string, not a parsed fingerprint. */
  FingerPrint *fp = parse_single_fingerprint(FP);
  if (fp != NULL) {
    checkFP(fp);
    delete fp;
    /* Print a blank line after checkFP's messages. */
    printf("\n");
  }

  if (dst - FP < 1)
    return -1;
  return 0;
}

/* When Nmap prints a fingerprint for submission, it sometimes
   includes duplicates of tests because 1 or more elements of that
   test differ.  While this is important for things like fingerfix
   (submission), other scripts can't handle it.  So this function
   removes the duplicates.  Maybe it should have more smarts, but
   currently it just keeps the first instance of each test.  Returns
   the number of duplicate tests (0 if there were none). The function
   quits and prints the problem if there is an error. */
int remove_duplicate_tests(FingerPrint *FP) {
  std::vector<FingerTest>::iterator outer, inner, prev;
  FingerTest tmp;
  int dupsfound = 0;
  if (!FP) { fatal("NULL FP passed to %s", __FUNCTION__); }

  for (outer = FP->tests.begin(); outer != FP->tests.end(); outer++) {
    /* We check if this test has any duplicates forward in the list,
       and if so, remove them */
    inner = FP->tests.end();
    inner--;
    while (inner != outer) {
      prev = inner;
      prev--;

      if (strcmp(outer->name, inner->name) == 0) {
        /* DUPLICATE FOUND!  REMOVE THE ONE W/THE FEWEST ATTRIBUTES */
        int outeratts = outer->results.size();
        int inneratts = inner->results.size();
        if (inneratts > outeratts) {
          /* We do a swap of members because we can't change the address of 'FP' */
          tmp = *outer;
          *outer = *inner;
          *inner = tmp;
        }
        dupsfound++;
        FP->tests.erase(inner);
      }

      inner = prev;
    }
  }
  return dupsfound;
}
