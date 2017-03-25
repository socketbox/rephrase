/* rephrase.c (the main program)
 * Copyright (C) 2003, 2014  Phil Lanch
 *
 * This file is part of Rephrase.
 *
 * Rephrase is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3.
 *
 * Rephrase is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define PROGRAM "rephrase"
#ifndef VERSION
#error VERSION must be defined
#endif

#ifndef GPG
#define GPG "/usr/local/bin/gpg"
#endif

#ifndef CRYPTSETUP
#define CRYPTSETUP "/sbin/cryptsetup"
#endif

#ifndef PATTERN_MAX
#define PATTERN_MAX 512
#endif
#define ALTERNATIVES_MAX ((PATTERN_MAX + 1) / 2)

#ifndef ARGS_MAX
#define ARGS_MAX 100
#endif

static const char LF = '\n';

struct profile {
  const char *option;
  char *command[ARGS_MAX + 1];
  short write_linefeed;
  int good_passphrase_status;
  int bad_passphrase_status;
};

struct profile profiles[] = {
  {
    "--gpg-key",
    { GPG, "--default-key", "%1", "--passphrase-fd", "0", "--batch", "--no-tty", "--dry-run", "--clearsign", "/dev/null", NULL },
    1,
    0,
    -1
  },
  {
    "--gpg-symmetric",
    { GPG, "--passphrase-fd", "0", "--batch", "--no-tty", "--decrypt", "%1", NULL },
    1,
    0,
    -1
  },
  {
    "--luks",
    { CRYPTSETUP, "--test-passphrase", "--key-file", "/dev/fd/0", "open", "--type", "luks", "%1", NULL },
    0,
    0,
    2
  },
  {
    NULL,
    { NULL },
    1,
    0,
    -1
  }
};

struct configuration {
  const char *path;
  char *argv[ARGS_MAX + 1];
  short write_linefeed;
  int good_passphrase_status;
  int bad_passphrase_status;
};

struct secrets {
  char pattern[PATTERN_MAX + 1];
  int alternatives[ALTERNATIVES_MAX];
  int try[ALTERNATIVES_MAX];
  int i, a, b, alt_n;
  short is_alt, is_literal, error;
  ssize_t io_count;
};

static void
read_pattern (struct secrets *s)
{
  FILE *tty_fp;
  struct termios term_save, term;
  int pattern_err;

  if (!(tty_fp = fopen ("/dev/tty", "r+"))) {
    perror ("fopen");
    exit (8);
  }
  if (tcgetattr (fileno (tty_fp), &term_save)) {
    perror ("tcgetattr");
    exit (9);
  }
  term = term_save;
  term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  if (tcsetattr (fileno (tty_fp), TCSAFLUSH, &term)) {
    perror ("(1st) tcsetattr");
    exit (10);
  }

  fprintf (tty_fp, "Enter pattern: ");
  fflush (tty_fp);
  for (s->i = 0, pattern_err = 0; s->i <= PATTERN_MAX; ++s->i) {
    while (!(s->io_count = read (fileno (tty_fp), s->pattern + s->i, 1))) {
      sleep (1);
    }
    if (s->io_count == -1) {
      fprintf (tty_fp, "\n");
      perror ("read");
      pattern_err = 11;
      break;
    }
    if (s->pattern[s->i] == '\n') {
      s->pattern[s->i] = '\0';
      fprintf (tty_fp, "\n");
      break;
    }
  }
  if (s->i > PATTERN_MAX) {
    do {
      while (!(s->io_count = read (fileno (tty_fp), s->pattern, 1))) {
        sleep (1);
      }
      if (s->io_count == -1) {
        fprintf (tty_fp, "\n");
        perror ("read");
        pattern_err = 11;
        break;
      }
    } while (*s->pattern != '\n');
    if (!pattern_err) {
      fprintf (tty_fp, "\n");
      fprintf (stderr, "Pattern is too long\n(maximum length is %d;"
          " you could redefine PATTERN_MAX and recompile)\n", PATTERN_MAX);
      pattern_err = 12;
    }
  }

  if (tcsetattr (fileno (tty_fp), TCSAFLUSH, &term_save)) {
    perror ("(2nd) tcsetattr");
    exit (pattern_err ? pattern_err : 13);
  }
  if (pattern_err) {
    exit (pattern_err);
  }
  if (fclose (tty_fp)) {
    perror ("fclose");
    exit (27);
  }
}

static void
parse_pattern (struct secrets *s)
{
  for (s->i = s->a = s->is_alt = s->error = 0; s->pattern[s->i] && !s->error;
          ++s->i) {
    switch (s->pattern[s->i]) {
      case '\\': ++s->i;
                 if (!s->pattern[s->i]) {
                   s->error = 1;
                 }
                 break;
      case '(':  if (s->is_alt) {
                   s->error = 1;
                 } else {
                   s->is_alt = 1;
                   s->alternatives[s->a] = 0;
                 }
                 break;
      case '|':  if (!s->is_alt) {
                   s->error = 1;
                 } else {
                   ++s->alternatives[s->a];
                 }
                 break;
      case ')':  if (!s->is_alt) {
                   s->error = 1;
                 } else {
                   s->is_alt = 0;
                   ++s->a;
                 }
                 break;
    }
  }
  if (s->error || s->is_alt) {
    fprintf (stderr, "Pattern is malformed\n");
    exit (14);
  }

  for (s->b = 0; s->b < s->a; ++s->b ) {
    s->try[s->b] = 0;
  }
}

static void
spawn_gpg (const char *path, char *argv[], int dev_null, int *pass_writer, pid_t *kid)
{
  int pass_fds[2];

  if (pipe (pass_fds)) {
    perror ("pipe");
    exit (16);
  }
  *pass_writer = pass_fds[1];

  if ((*kid = fork ()) == -1) {
    perror ("fork");
    exit (17);
  }

  if (!*kid) {
    if (close (pass_fds[1])) {
      perror ("(kid) close");
      exit (18);
    }
    if (dup2 (pass_fds[0], 0) == -1 || dup2 (dev_null, 1) == -1
        || dup2 (dev_null, 2) == -1) {
      perror ("(kid) dup2");
      exit (19);
    }
    execv (path, argv);
    perror ("(kid) execv");
    exit (20);
  }

  if (close (pass_fds[0])) {
    perror ("(parent) close");
    exit (21);
  }
}

static void
write_passphrase (struct secrets *s, short write_linefeed, int pass_writer)
{
  for (s->i = s->b = 0; s->pattern[s->i]; ++s->i) {
    switch (s->pattern[s->i]) {
      case '\\': ++s->i;
                 s->is_literal = 1;
                 break;
      case '(':  s->is_alt = 1;
                 s->alt_n = 0;
                 s->is_literal = 0;
                 break;
      case '|':  ++s->alt_n;
                 s->is_literal = 0;
                 break;
      case ')':  s->is_alt = 0;
                 ++s->b;
                 s->is_literal = 0;
                 break;
      default:   s->is_literal = 1;
                 break;
    }
    if (s->is_literal && (!s->is_alt || s->alt_n == s->try[s->b])) {
      while (!(s->io_count = write (pass_writer, s->pattern + s->i, 1))) {
        sleep (1);
      }
      if (s->io_count == -1) {
        perror ("write");
        exit (22);
      }
    }
  }
  if (write_linefeed != 0) {
    while (!(s->io_count = write (pass_writer, &LF, 1))) {
      sleep (1);
    }
    if (s->io_count == -1) {
      perror ("(last) write");
      exit (23);
    }
  }

  if (close (pass_writer)) {
    perror ("(final) close");
    exit (24);
  }
}

static int
passphrase_is_correct (struct configuration *c, struct secrets *s, int dev_null)
{
  int pass_writer;
  pid_t kid;
  int status;

  spawn_gpg (c->path, c->argv, dev_null, &pass_writer, &kid);

  write_passphrase (s, c->write_linefeed, pass_writer);

  if (waitpid (kid, &status, 0) == -1) {
    perror ("waitpid");
    exit (25);
  }
  if (!WIFEXITED (status)) {
    fprintf (stderr, "%s didn't exit normally\n", c->path);
    exit (26);
  }
  if (WEXITSTATUS (status) == c->good_passphrase_status) {
    return 1;
  }
  if (c->bad_passphrase_status == -1 || WEXITSTATUS (status) == c->bad_passphrase_status) {
    return 0;
  }
  fprintf (stderr, "%s had unexpected exit status %d (perhaps you didn't specify a valid key/file/device)\n", c->path, WEXITSTATUS (status));
  exit (29);
}

static int
find_passphrase (struct configuration *c, struct secrets *s)
{
  int dev_null;

  if ((dev_null = open ("/dev/null", O_RDWR)) == -1) {
    perror ("open");
    exit (15);
  }

  do {
    if (passphrase_is_correct (c, s, dev_null)) {
      fprintf (stderr, "Passphrase found\n");
      for (s->b = 0; s->b < s->a; ++s->b) {
        printf (s->b ? " %d" : "%d", s->try[s->b] + 1);
      }
      printf ("\n");
      return (0);
    }

    s->error = 1;
    for (s->b = s->a - 1; s->b >= 0; --s->b) {
      if (s->try[s->b] < s->alternatives[s->b]) {
        ++s->try[s->b];
        for (s->i = s->b + 1; s->i < s->a; ++s->i) {
          s->try[s->i] = 0;
        }
        s->error = 0;
        break;
      }
    }
  } while (!s->error);

  fprintf (stderr, "Passphrase doesn't match pattern (or no such key/file/device)\n");
  return (1);
}

int
main (int argc, char **argv)
{
  struct secrets sec;
  struct configuration conf;
  struct stat stat_buf;
  int p, c;
  char *param;

  fprintf (stderr, "%s (Rephrase) %s\nCopyright (C) 2003, 2014  Phil Lanch\n"
      "This program comes with ABSOLUTELY NO WARRANTY.\n"
      "This is free software, and you are welcome to redistribute it\n"
      "under certain conditions.  See the file COPYING for details.\n\n",
      PROGRAM, VERSION);

  if (mlock (&sec, sizeof (struct secrets))) {
    perror ("mlock");
    fprintf (stderr, "(%s should be installed setuid root)\n", PROGRAM);
    exit (2);
  }
  if (setreuid (getuid (), getuid ())) {
    perror ("setreuid");
    exit (3);
  }
  /* rephrase shouldn't have the setgid bit set.  just in case it was
   * set anyway, we'll drop any setgid privileges.
   */
  if (setregid (getgid (), getgid ())) {
    perror ("setregid");
    exit (28);
  }

  p = -1;
  if (argc == 2 && *argv[1] != '-') {
    p = 0;
    param = argv[1];
  } else if (argc == 3) {
    for (p = 0; profiles[p].option; ++p) {
      if (strcmp(profiles[p].option, argv[1]) == 0) {
        break;
      }
    }
    if (profiles[p].option) {
      param = argv[2];
    } else {
      p = -1;
    }
  }
  if (p == -1) {
    fprintf (stderr, "Usage: %s <key> | --gpg-key <key> | --gpg-symmetric <encrypted_file> | --luks <block_device>\n", PROGRAM);
    exit (7);
  }

  conf.path = profiles[p].command[0];
  for (c = 0; profiles[p].command[c]; ++c) {
    if (c >= ARGS_MAX) {
      fprintf (stderr, "Command contains too many arguments\n(maximum is %d; "
          "you could redefine ARGS_MAX and recompile)\n", ARGS_MAX);
      exit (30);
    }
    if (c == 0) {
      if (*profiles[p].command[c] != '/') {
        fprintf (stderr, "Command doesn't begin with a full path\n");
        exit (31);
      }
      conf.argv[c] = rindex (profiles[p].command[c], '/') + 1;
      if (*conf.argv[c] == '\0') {
        fprintf (stderr, "Command contains nothing but slashes\n");
        exit (32);
      }
    } else if (strcmp(profiles[p].command[c], "%1") == 0) {
      conf.argv[c] = param;
    } else {
      conf.argv[c] = profiles[p].command[c];
    }
  }
  if (c == 0) {
    fprintf (stderr, "No command specified\n");
    exit (34);
  }
  conf.argv[c] = NULL;
  conf.write_linefeed = profiles[p].write_linefeed;
  conf.good_passphrase_status = profiles[p].good_passphrase_status;
  conf.bad_passphrase_status = profiles[p].bad_passphrase_status;

  if (stat (conf.path, &stat_buf)) {
    if (errno & (ENOENT | ENOTDIR)) {
      fprintf (stderr, "%s does not exist (or is in a directory I cannot read)"
          "\n", conf.path);
      exit (4);
    }
    perror ("stat");
    exit (5);
  }
  if (!S_ISREG(stat_buf.st_mode)
      || !(stat_buf.st_mode & (stat_buf.st_uid == getuid () ? S_IXUSR
      : stat_buf.st_gid == getgid () ? S_IXGRP : S_IXOTH))) {
    fprintf (stderr, "%s is not an executable (by me) file\n", conf.path);
    exit (6);
  }

  read_pattern (&sec);

  parse_pattern (&sec);

  return (find_passphrase (&conf, &sec));
}
