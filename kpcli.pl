#!/usr/bin/perl

###########################################################################
#
# kpcli - KeePass Command Line Interface
#
# Author: Lester Hightower <hightowe at cpan dot org>
#
# This program was inspired by "kedpm -c" and resulted despite illness
# (or more likely because of it) over the USA Thanksgiving holiday in
# late November of 2010. As a long-time user of the Ked Password Manager
# I really missed a command line interface after getting an Android cell
# phone and switching to KeePass, so that I could access my password
# database on my phone. This program scratches that itch.
#
###########################################################################

# The required perl modules
use strict;                                   # core
use version;                                  # core
use FileHandle;                               # core
use Getopt::Long;                             # core
use File::Basename;                           # core
use Digest::file;                             # core
use Digest::SHA qw(sha256);                   # core
use Data::Dumper qw(Dumper);                  # core
use Term::ReadLine;                           # core
use Term::ANSIColor;                          # core
use Carp qw(longmess);                        # core
use Time::HiRes qw(gettimeofday tv_interval); # core
use POSIX;                   # core, required for unsafe signal handling
use Crypt::Rijndael;         # non-core, libcrypt-rijndael-perl on Ubuntu
use Sort::Naturally;         # non-core, libsort-naturally-perl on Ubuntu
use Term::ReadKey;           # non-core, libterm-readkey-perl on Ubuntu
use Term::ShellUI;           # non-core, libterm-shellui-perl on Ubuntu
                             #  - add Term::ReadLine::Gnu for cli history
use File::KeePass 0.03;      # non-core, libfile-keepass-perl on Ubuntu
                             #  - >=v0.03 needed due critical bug fixes
# Pull in optional perl modules with run-time loading
my %OPTIONAL_PM=();
# Data::Password is needed for the pwck command (check password quality).
if  (eval {require Data::Password;1;} eq 1) {
  Data::Password->import( qw(IsBadPassword) );
  $Data::Password::MINLEN = 8;
  $Data::Password::MAXLEN = 0;
  $OPTIONAL_PM{'Data::Password'}->{loaded} = 1;
} else {
  $OPTIONAL_PM{'Data::Password'}->{loaded} = 0;
}
# Capture::Tiny is needed to safely optionally-load Clipboard.
if  (eval {require Capture::Tiny;1;} eq 1) {
  Capture::Tiny->import( qw(capture) );
  $OPTIONAL_PM{'Capture::Tiny'}->{loaded} = 1;
} else {
  $OPTIONAL_PM{'Capture::Tiny'}->{loaded} = 0;
}
# Clipboard is needed by the clipboard copy commands (xw, xu, xp, and xx).
if ($OPTIONAL_PM{'Capture::Tiny'}->{loaded}
				&& (eval {require Clipboard;1;} eq 1)) {
  # Clipboard tests its dependencies at import() and writes warnings to STDERR.
  # Tiny::Capture is used to catch those warnings and we silently hold them
  # until and unless someone tries to use dependant functions.
  sub import_clipboard { Clipboard->import(); }
  my ($out, $err, @result) = capture(\&import_clipboard);
  if (length($err)) {
    # Cleanup the error message for for better viewing by the user
    $err =~ s/^\s+//g; $err =~ s/\s+$//g; $err =~ s/^(.*)$/ > $1/mg;
    $OPTIONAL_PM{'Clipboard'}->{error} = $err;
    $OPTIONAL_PM{'Clipboard'}->{loaded} = 0;
  } else {
    $OPTIONAL_PM{'Clipboard'}->{loaded} = 1;
  }
} else {
  $OPTIONAL_PM{'Clipboard'}->{loaded} = 0;
}

$|=1; # flush immediately after writes or prints to STDOUT

my $DEBUG=0;
$Data::Dumper::Useqq = 1;    # Have Dumper escape special chars (like \0)
my $DEFAULT_ENTRY_ICON = 0;  # In keepassx, icon 0 is a golden key
my $DEfAULT_GROUP_ICON = 49; # In keepassx, icon 49 is an opened file folder
my $FOUND_DIR = '_found';    # The find command's results go in /_found/

# Application name and version
my $APP_NAME = basename($0);  $APP_NAME =~ s/\.pl$//;
my $VERSION = "2.2";

our $HISTORY_FILE = ""; # Gets set in the MyGetOpts() function
my $opts=MyGetOpts();   # Will only return with options we think we can use

# Setup our Term::ShellUI object
my $term = new Term::ShellUI(
    app => $APP_NAME,
    history_file => $HISTORY_FILE,
    keep_quotes => 0,
    commands => {
         #"" => { args => sub { shift->complete_history(@_) } },
         "history" => { desc => "Prints the command history",
            doc => "\nSpecify a number to list the last N lines of history" .
            "Pass -c to clear the command history, " .
            "-d NUM to delete a single item\n",
            args => "[-c] [-d] [number]",
            method => sub { shift->history_call(@_) },
	    exclude_from_history => 1,
         },
         "version" => {
             desc => "Print the version of this program",
             method => sub { print "$VERSION\n"; },
	     exclude_from_history => 1,
         },
         "ver" => { alias => "version",
		exclude_from_completion=>1, exclude_from_history => 1,},
         "help" => {
             desc => "Print helpful information",
             args => sub { shift->help_args(undef, @_); },
             method => sub { my_help_call(@_); },
	     exclude_from_history => 1,
             #method => sub { shift->help_call(undef, @_); }
         },
         "h" => { alias => "help",
		exclude_from_completion=>1, exclude_from_history => 1,},
         "?" => { alias => "help",
		exclude_from_completion=>1, exclude_from_history => 1,},
         "cl" => {
             desc => "Change directory and list entries (cd+ls)",
             doc => "\n" .
		"Change the pwd to an absolute or relative path\n" .
		"and list the entries there. This is a useful way\n" .
		"to quickly navigate to a path and have the entries\n" .
		"listed in preparation to run the show command.\n",
             maxargs => 1,
             args => \&complete_groups,
             method => sub { if(cli_cd(@_) == 0) { cli_ls() } },
         },
	 "cls" => {
	     desc => 'Clear screen ("clear" command also works)',
	     doc  => "\n" .
		"Clear the screen, which is useful when guests arrive.\n",
	     maxargs => 0,
	     method => sub { print "\033[2J\033[0;0H"; },
	     exclude_from_history => 1,
	 },
         "clear" => { alias => "cls", exclude_from_history => 1, },
         "cd" => {
             desc => "Change directory (path to a group)",
             doc => "\n" .
		"Change the pwd to an absolute or relative path.\n" .
		"Slashes in names are escaped with backslashes:\n" .
		"(i.e. \"cd /personal/Comcast\\/Xfinity\").\n",
             maxargs => 1,
             args => \&complete_groups,
             method => \&cli_cd,
         },
         "chdir" => { alias => 'cd' },
         "saveas" => {
             desc => "Save to a specific filename " .
				"(saveas <file.kdb> [<file.key>])",
             minargs => 1, maxargs => 2,
             args => [\&Term::ShellUI::complete_files,
					\&Term::ShellUI::complete_files],
             proc => \&cli_saveas,
         },
         "export" => {
             desc => "Export entries to a new KeePass DB " .
				"(export <file.kdb> [<file.key>])",
             doc => "\n" .
		"Use this command to export the full tree of groups\n" .
		"and entries to another KeePass database file on disk,\n" .
		"starting at your current path (pwd).\n" .
		"\n" .
		"This is also a \"safer\" way to change your database\n" .
		"password. Export from /, verify that the new file is\n" .
		"good, and then remove your original file.\n",
             minargs => 1, maxargs => 2,
             args => [\&Term::ShellUI::complete_files,
					\&Term::ShellUI::complete_files],
             proc => \&cli_export,
         },
         "import" => {
             desc => "Import another KeePass DB " .
				"(import <file.kdb> <path> [<file.key>])",
             doc => "\n" .
		"Use this command to import the entire KeePass DB\n" .
		"specified by <file.kdb> into a new group at <path>.\n",
             minargs => 2, maxargs => 3,
             args => [\&Term::ShellUI::complete_files,\&complete_groups,
					\&Term::ShellUI::complete_files],
             proc => \&cli_import,
         },
         "open" => {
             desc => "Open a KeePass database file " .
				"(open <file.kdb> [<file.key>])",
             minargs => 1, maxargs => 2,
             args => [\&Term::ShellUI::complete_files,
					\&Term::ShellUI::complete_files],
             proc => \&cli_open,
         },
         "mkdir" => {
             desc => "Create a new group (mkdir <group_name>)",
             minargs => 1, maxargs => 1,
             args => \&complete_groups,
             method => \&cli_mkdir,
         },
         "rmdir" => {
             desc => "Delete a group (rmdir <group_name>)",
             minargs => 1, maxargs => 1,
             args => \&complete_groups,
             method => \&cli_rmdir,
         },
         "ls" => {
             desc => "Lists entries in pwd or in the specified path",
             minargs => 0, maxargs => 1,
             args => \&complete_groups,
             method => \&cli_ls,
         },
         "new" => {
             desc => "Create a new entry in the current group (pwd)",
             minargs => 0, maxargs => 0, args => "",
             method => \&cli_new,
         },
         "rm" => {
             desc => "Remove an entry: rm <path to entry|entry number>",
             minargs => 1, maxargs => 1,
             args => \&complete_groups_and_entries,
             method => \&cli_rm,
         },
         "xu" => {
             desc => "Copy username to clipboard: xu <entry path|number>",
             minargs => 1, maxargs => 1,
             args => \&complete_groups_and_entries,
             method => sub { cli_xN('xu', @_); }
         },
         "xw" => {
             desc => "Copy URL (www) to clipboard: xw <entry path|number>",
             minargs => 1, maxargs => 1,
             args => \&complete_groups_and_entries,
             method => sub { cli_xN('xw', @_); }
         },
         "xp" => {
             desc => "Copy password to clipboard: xp <entry path|number>",
             minargs => 1, maxargs => 1,
             args => \&complete_groups_and_entries,
             method => sub { cli_xN('xp', @_); }
         },
         "xx" => {
             desc => "Clear the clipboard: xx",
             minargs => 0, maxargs => 0,
             method => sub { cli_xN('xx'); }
         },
         "pwck" => {
             desc => "Check password quality: pwck <entry|group>",
             doc => "\n" .
		"The pwck command test password quality for entries.\n" .
		"You can check an individual entry or all entries inside\n" .
		"of a group, recursively. To check every password in your\n" .
		"database, use: pwck /\n" .
		"",
             minargs => 1, maxargs => 1,
             args => \&complete_groups_and_entries,
             method => \&cli_pwck,
         },
         "stats" => {
             desc => "Prints statistics about the open KeePass file",
             method => \&cli_stats,
         },
         "show" => {
             desc => "Show an entry: show [-f] [-a] <entry path|entry number>",
             doc => "\n" .
		"The show command tries to intelligently determine\n" .
		"what you want to see and to make it easy to display.\n" .
		"Show can take a path to an entry as its argument or\n" .
		"an entry number as shown by the ls command.\n" .
		"\n" .
		"When using entry numbers, they will refer to the last\n" .
		"path when an ls was performed or pwd if ls has not\n" .
		"yet been run.\n" .
		"\n" .
		"By default, passwords are \"hidden\" by being displayed as\n" .
		"\"red on red\" where they can be copied to the clip board\n" .
		"but not seen. Provide the -f option to show passwords.\n" .
		"Use the -a option to see create and modified times, and\n" .
		"the index of the icon set for the entry.\n" .
		"",
             minargs => 1, maxargs => 3,
             args => \&complete_groups_and_entries,
             method => \&cli_show,
         },
         "edit" => {
             desc => "Edit an entry: edit <path to entry|entry number>",
             minargs => 1, maxargs => 1,
             args => \&complete_groups_and_entries,
             method => \&cli_edit,
         },
         "mv" => {
             desc => "Move an entry: mv <path to entry> <path to group>",
             minargs => 2, maxargs => 2,
             args => [\&complete_groups_and_entries, \&complete_groups],
             method => \&cli_mv,
         },
         "rename" => {
             desc => "Rename a group: rename <path to group>",
             minargs => 1, maxargs => 1,
             args => \&complete_groups,
             method => \&cli_rename,
         },
         "save" => {
             desc => "Save the database to disk",
             minargs => 0, maxargs => 0, args => "",
             method => \&cli_save,
         },
         "close" => {
             desc => "Close the currently opened database",
             minargs => 0, maxargs => 0, args => "",
             method => \&cli_close,
         },
         "find" => {
             desc => "Finds entries by Title",
             doc => "\n" .
		"Searches for entries with the given search term\n" .
		"in their title and places matches into \"/$FOUND_DIR/\".\n",
             minargs => 1, maxargs => 1, args => "<search string>",
             method => \&cli_find,
         },
         "pwd" => {
             desc => "Print the current working directory",
             maxargs => 0, proc => \&cli_pwd,
         },
         "icons" => {
             desc => "Change group or entry icons in the database",
             maxargs => 0, proc => \&cli_icons,
         },
         "quit" => {
             desc => "Quit this program (EOF and exit also work)",
             maxargs => 0, method => \&cli_quit,
	     exclude_from_history => 1,
         },
         "exit" => { alias => "quit", exclude_from_history => 1,}
       },
    );
$term->prompt(\&term_set_prompt);

# Seed our state global variable
our $state={
	'appname' => $APP_NAME,
	'term' => $term,
	'OPTIONAL_PM' => \%OPTIONAL_PM,
	'kdb_has_changed' => 0,
	'last_ls_path' => '',
	'put_master_passwd' => \&put_master_passwd,
	'get_master_passwd' => \&get_master_passwd,
	};
# If given --kdb=, open that file
if (length($opts->{kdb})) {
  my $err = open_kdb($opts->{kdb}, $opts->{key}); # Sets $state->{'kdb'}
  if (length($err)) {
    print "Error opening file: $err\n";
  }
} else {
  new_kdb($state);
}

# Enter the interative kpcli shell session
print "\n" .
	"KeePass CLI ($APP_NAME) v$VERSION is ready for operation.\n" .
	"Type 'help' for a description of available commands.\n" .
	"Type 'help <command>' for details on individual commands.\n";
if ($DEBUG) {print 'Using '.$term->{term}->ReadLine." for readline.\n"; }
if (! $DEBUG && $term->{term}->ReadLine ne 'Term::ReadLine::Gnu') {
  warn "* Please install Term::ReadLine::Gnu for better functionality!\n";
}
# My patch made it into Term::ShellUI v0.9, but I still chose not to make
# this script demand >=0.9 and instead look for the add_eof_exit_hook() and
# use it if it exists and warn if not.
if (Term::ShellUI->can('add_eof_exit_hook')) {
  $term->add_eof_exit_hook(\&eof_exit_hook);
} else {
  warn "* Please upgrade Term::ShellUI to version 0.9 or newer.\n";
}
print "\n";

setup_signal_handling(); # Exactly what the name indicates...

$term->run();

exit;

############################################################################
############################################################################
############################################################################

sub open_kdb($$) {
  my $file=shift @_;
  my $key_file=shift @_;
  our $state;

  # Make sure the file exists and is readable
  if (! -f $file) {
    return "File does not exist: $file";
  }
  if (! -r $file) {
    return "File is not readable: $file";
  }

  # Look for lock file and warn if it is found
  my $lock_file = $file . '.lock'; # KeePassX style
  if (-f $lock_file) {
    my $bold="\e[1m";
    my $red="\e[31m";
    my $yellow="\e[33m";
    my $clear="\e[0m";
    print $bold . $yellow .
	"WARNING:" .
	$clear .
	$red .
	       " A KeePassX-style lock file is in place for this file.\n" .
	"         It may be opened elsewhere." .
				"$yellow$bold  Be careful of saving!\n" .
	$clear;
  } else {
    $state->{placed_lock_file} = $lock_file;
  }

  # Ask the user for the master password and then open the kdb
  my $master_pass=GetMasterPasswd();
  $state->{kdb} = File::KeePass->new;
  if (! eval { $state->{kdb}->load_db($file,
			composite_master_pass($master_pass, $key_file)) }) {
    die "Couldn't load the file $file: $@";
  }

  if ($state->{placed_lock_file}) {
    touch_file($state->{placed_lock_file});
  }

  $state->{kdb_file} = $file;
  $state->{key_file} = $key_file;
  $state->{put_master_passwd}($master_pass);
  $state->{kdb_has_changed}=0;
  $master_pass="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  # Build the %all_grp_paths_fwd and %all_grp_paths_rev structures
  refresh_state_all_paths();

  # Store the md5sum of the file so we can watch for unexpected changes
  $state->{kdb_file_md5} = Digest::file::digest_file_hex($file, "MD5");

  # Initialize our state into "/"
  cli_cd($term, {'args' => ["/"]});

  return ''; # If we return anything else it is an error message
}

# Called by Term::ShellUI to get the user prompt
sub term_set_prompt($$) {
  my $term=shift @_;
  my $raw_cmd=shift @_;
  our $state;

  my $pwd=$state->{all_grp_paths_rev}->{$state->{path}->{id}};
  $pwd =~ s%/%\\/%g;
  $pwd =~ s/\0/\//g;

  my $app=$state->{appname};
  my $pwd=get_pwd();
  return "$app:$pwd> ";
}

# Walks through a tree of groups building a flat hash of NULL-separated
# paths to group IDs. Called on the root to build a full path tree.
sub build_all_group_paths {
  my $hash = shift @_;
  my $g = shift @_;
  my $root_path = shift @_ || [];

  my $bold="\e[1m";
  my $red="\e[31m";
  my $yellow="\e[33m";
  my $clear="\e[0m";

  foreach my $me (@{$g}) {
    my @path_to_me = @{$root_path};
    push @path_to_me, $me->{title};
    my $path=join("\0",@path_to_me);
    my $err_path = '/' . humanize_path($path);
    if (defined($hash->{$path})) {
      print $bold . $yellow .  "WARNING: " . $clear .
		$red . "Multiple groups titled: $err_path!\n" .
		$red . "This is unsupported and may cause data loss!\n" .
		$clear;
    }
    $hash->{$path}=$me->{id};

    if (defined($me->{groups})) {
      build_all_group_paths($hash,$me->{groups},\@path_to_me);
    }
  }
  return (scalar(keys(%{$hash})));
}

# Walks through a tree of groups building a flat hash of NULL-separated
# paths to entry IDs. Called on the root to build a full path tree.
sub build_all_entry_paths {
  my $hash = shift @_;
  my $g = shift @_;
  my $root_path = shift @_ || [];

  my $bold="\e[1m";
  my $red="\e[31m";
  my $yellow="\e[33m";
  my $clear="\e[0m";

  foreach my $me (@{$g}) {
    my @path_to_me = @{$root_path};
    push @path_to_me, $me->{title};
    if (defined($me->{entries})) {
      foreach my $ent (@{$me->{entries}}) {
        my $path=join( "\0", (@path_to_me, $ent->{title}) );
        my $err_path = '/' . humanize_path($path);
        if ($ent->{title} eq '') {
          print $bold . $yellow .  "WARNING: " . $clear .
		$red . "There is an entry with a blank title in $err_path!\n" .
		$clear;
        }
        if (defined($hash->{$path}) &&
				$err_path !~ m/\/Backup\/|\/Meta-Info$/) {
          print $bold . $yellow .  "WARNING: " . $clear .
		$red . "Multiple entries titled: $err_path!\n" .
		$red . "This is unsupported and may cause data loss!\n" .
		$clear;
        }
        $hash->{$path}=$ent->{id};
      }
    }

    if (defined($me->{groups})) {
      build_all_entry_paths($hash,$me->{groups},\@path_to_me);
    }
  }
  return (scalar(keys(%{$hash})));
}

# Returns the current path the user is sitting in.
sub get_pwd {
  my $pwd='';
  if (defined($state->{all_grp_paths_rev}->{$state->{path}->{id}})) {
    $pwd=$state->{all_grp_paths_rev}->{$state->{path}->{id}};
  }
  $pwd =~ s%/%\\/%g;
  $pwd =~ s/\0/\//g;
  $pwd = '/' . $pwd;
return $pwd;
}

# Destroys our /_found group (where we place search results)
sub destroy_found {
  our $state;
  # Look for an exising /_found and kill it if it exists
  my $k=$state->{kdb};
  my $found_group=$k->find_group({level=>0,title=>$FOUND_DIR});
  if (defined($found_group)) {
    my @oldents = $k->find_entries({group=>$found_group->{id}});
    foreach my $ent (@oldents) {
      $k->delete_entry({id => $ent->{id}});
    }
    $k->delete_group({level=>0,title=>$FOUND_DIR});

    # Because we destroyed /_found we must refresh our $state paths
    refresh_state_all_paths();
  }
}

# Refreshes $state->{all_grp_paths_fwd} and $state->{all_grp_paths_rev}
sub refresh_state_all_paths() {
  our $state;

  # Build all group paths
  my %all_grp_paths_fwd;
  build_all_group_paths(\%all_grp_paths_fwd,$state->{kdb}->groups);
  my %all_grp_paths_rev = reverse %all_grp_paths_fwd;
  $state->{all_grp_paths_fwd}=\%all_grp_paths_fwd;
  $state->{all_grp_paths_rev}=\%all_grp_paths_rev;

  # Build all entry paths
  my %all_ent_paths_fwd;
  build_all_entry_paths(\%all_ent_paths_fwd,$state->{kdb}->groups);
  my %all_ent_paths_rev = reverse %all_ent_paths_fwd;
  $state->{all_ent_paths_fwd}=\%all_ent_paths_fwd;
  $state->{all_ent_paths_rev}=\%all_ent_paths_rev;
}

# Gathers the list of groups and entries for the pwd we're sitting in
sub get_current_groups_and_entries {
 return get_groups_and_entries(get_pwd());
}
sub get_groups_and_entries {
  my $path=shift @_;
  our $state;

  my $k=$state->{kdb};

  my @groups=();
  my @entries=();
  my $norm_path = normalize_path_string($path);
  if (length($norm_path) < 1) {
    @groups = $k->find_groups({level=>0});
    @entries = $k->find_entries({level => 0});
  } else {
    my $id=$state->{all_grp_paths_fwd}->{$norm_path};
    my ($this_grp,@trash) = $k->find_groups({id=>$id});
    if (defined($this_grp->{groups})) { # subgroups
      @groups = @{$this_grp->{groups}};
    }
    @entries = $k->find_entries({group_id => $id});
  }

  @groups = sort group_sort @groups;
  @entries = sort { ncmp($a->{title},$b->{title}); } @entries;

  return (\@groups,\@entries);
}

# This function takes a group ID and returns all of the child
# groups of that group, flattened.
sub all_child_groups_flattened($) {
  my $group_id=shift @_;
  our $state;

  my $k=$state->{kdb};
  my @groups=();
  my ($this_grp,@trash) = $k->find_groups({id=>$group_id});
  if (defined($this_grp->{groups})) { # subgroups
    @groups = @{$this_grp->{groups}};
    foreach my $child_group (@groups) {
      push @groups, all_child_groups_flattened($child_group->{id});
    }
  }

  return @groups;
}

# A function to properly sort groups by title
sub group_sort($$) {
  my $a=shift @_;
  my $b=shift @_;

  # _found at level 0 is a special case (from our find command).
  if ($a->{title} eq $FOUND_DIR && $a->{level} == 0) {
    return 1;
  } elsif ($b->{title} eq $FOUND_DIR && $b->{level} == 0) {
    return -1;
  # Backup at level=0 is a special case (KeePassX's Backup group).
  } elsif ($a->{title} eq 'Backup' && $a->{level} == 0) {
    return 1;
  } elsif ($b->{title} eq 'Backup' && $b->{level} == 0) {
    return -1;
  # Sort everything else naturally (Sort::Naturally::ncmp).
  } else {
    return ncmp($a->{title},$b->{title}); # Natural sort
  }


}

# -------------------------------------------------------------------------
# All of the cli_*() functions are below here
# -------------------------------------------------------------------------

# Checks passwords for their quality
sub cli_pwck {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  # If Data::Password is not avaiable we can't do this for the user
  if  (! $state->{OPTIONAL_PM}->{'Data::Password'}->{loaded}) {
    print "Error: pwck requires the Data::Password module.\n";
    return;
  }

  my @targets = ();
  my $target = $params->{args}->[0];
  # Start by trying to find a single entity with the paramter given.
  # If no single entity is found then try to find entities based on
  # assuming that the path given is a group.
  my $ent=find_target_entity_by_number_or_path($target);
  if (defined($ent)) {
    push @targets, $ent;
  } else {
    my @groups = ();
    my $target = normalize_path_string($target);
    if ($target eq '' || $target eq '.' && get_pwd() eq '/') {
      @groups = $state->{kdb}->find_groups({}); # Every group in the file!
    } elsif (defined($state->{all_grp_paths_fwd}->{$target})) {
      my $group_id = $state->{all_grp_paths_fwd}->{$target};
      my $this_grp = $state->{kdb}->find_group( { id => $group_id } );
      @groups = all_child_groups_flattened($group_id);
      push @groups, $this_grp; # Push this group onto its children
    }
    # Loop over each target group adding each of its entries as targets
    foreach my $group (@groups) {
      if (defined($group->{entries})) {
        push @targets, @{$group->{entries}};
      }
    }
  }

  # Test each password, collect the results and record empty passwords
  my %results=();
  my @empties = ();
  print "  working...\r";
  my @busy_chars = qw(\ | / -); my $i=0; my $in=10;
  foreach my $ent (@targets) {
    printf "%s\r", $busy_chars[int($i/$in)%($#busy_chars+1)] if (!($i++ % $in));
    my $pass = $state->{kdb}->locked_entry_password($ent);
    if (length($pass) == 0) {
      push @empties, $ent;
      $results{$ent->{id}} = '';
    } else {
      $results{$ent->{id}} = IsBadPassword($pass);
      if ($results{$ent->{id}} =~ m/dictionary word/i) {
        # IsBadPassword() reports dictionary words that it finds. I don't
        # like that from a security perspective so we change that here.
        $results{$ent->{id}} = "contains a dictionary word";
      }
    }
    # If the user hit ^C (SIGINT) then we need to stop
    if (defined($state->{signals}->{INT}) &&
			tv_interval($state->{signals}->{INT}) < 0.25) {
       print "\r"; # Need to return to column 0 of the output line
       return 0;
    }
  }

  # If we only analyzed one password, return singular-style results
  if (scalar(@targets) == 1) {
    my $ent=$targets[0];
    if (length($results{$ent->{id}})) {
      print "Password concerns: " . $results{$ent->{id}} . "\n";
    } elsif (scalar(@empties) > 0) {
      print "Password field is empty.\n";
    } else {
      print "Password strength is good.\n";
    }
  } else {
  # If we analyzed more than one password, return multiple-style results
    my %problems=();
    foreach my $ent_id (keys %results) {
      if (length($results{$ent_id})) {
        $problems{$state->{all_ent_paths_rev}->{$ent_id}} = $ent_id;
      }
    }
    my $analyzed = scalar(@targets);
    my $problem_count = scalar(keys %problems);
    my $empty_count = scalar(@empties);
    print "$analyzed passwords analyzed, $empty_count blank, " .
					"$problem_count concerns found";
    if ($problem_count > 0) { print ":"; } else { print "."; }
    print "\n";
    foreach my $path (sort keys %problems) {
      print humanize_path($path) . ": $results{$problems{$path}}\n";
    }
  }

  return 0;
}

# Prints some statistics about the open KeePass file
sub cli_stats {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  # Group and entry counts
  my %stats;
  $stats{group_count} = scalar(keys(%{$state->{all_grp_paths_fwd}}));
  $stats{entry_count} = scalar(keys(%{$state->{all_ent_paths_fwd}}));

  # Password lengths
  my $k=$state->{kdb};
  my %password_lengths;
  print "  working...\r";
  my @busy_chars = qw(\ | / -); my $i=0; my $in=100;
  foreach my $ent_id (values(%{$state->{all_ent_paths_fwd}})) {
    printf "%s\r", $busy_chars[int($i/$in)%($#busy_chars+1)] if (!($i++ % $in));
    my $ent = $k->find_entry({id => $ent_id});
    my $pass_len = length($k->locked_entry_password($ent));
    if ($pass_len < 1) {
      $password_lengths{"0"}++;
    } elsif ($pass_len > 0 && $pass_len < 8) {
      $password_lengths{"1-7"}++;
    } elsif ($pass_len > 7 && $pass_len < 12) {
      $password_lengths{"8-11"}++;
    } elsif ($pass_len > 11 && $pass_len < 17) {
      $password_lengths{"12-16"}++;
    } elsif ($pass_len > 16 && $pass_len < 20) {
      $password_lengths{"17-19"}++;
    } elsif ($pass_len > 19) {
      $password_lengths{"20+"}++;
    }
    # If the user hit ^C (SIGINT) then we need to stop
    if (defined($state->{signals}->{INT}) &&
                        tv_interval($state->{signals}->{INT}) < 0.25) {
       print "\r"; # Need to return to column 0 of the output line
       return 0;
    }
  }

  print "KeePass file version: " . $k->{header}->{version} . "\n" .
	"Encryption type:      " . $k->{header}->{enc_type} . "\n" .
	"Encryption rounds:    " . $k->{header}->{rounds} . "\n" .
	"Number of groups:     $stats{group_count}\n" .
	"Number of entries:    $stats{entry_count}\n" .
	"Entries with passwords of length:\n".stats_print(\%password_lengths) .
	"\n" .
	"";
}

sub cli_pwd {
  print get_pwd() . "\n";
}

sub cli_cd {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  my $raw_pathstr = $params->{args}->[0];
  # "cd ."
  if ($raw_pathstr =~ m/^[.]$/) {
    return; # nothing to do
  }
  # "cd -"
  if ($raw_pathstr =~ m/^[-]$/) {
    return cli_cd($self, {'args' => [$state->{oldpwd}]});
  }
  # Everything else is handled by helpers
  return cli_cd_helper($state,normalize_path_string($raw_pathstr));
}

# Takes a possibly wacky path with ".."s and such and normalizes it into a
# NULL-separated path that can be used as a key into $state->{all_grp_paths_fwd}
sub normalize_path_string($) {
  my $path_string = shift @_;
  our $state;

  # Split the path into @path
  # http://efreedom.com/Question/1-3588341/Implement-Escape-Sequence-Using-Split-Perl
  my $delim="/";
  my $escape="\\";
  my @path = $path_string =~
	/(?:\Q$delim\E|^)((?>(?:\Q$escape\E.|(?!\Q$delim\E).)*))/gs;
	#/(?:\Q$delim\E|^)((?:\Q$escape\E.|(?!\Q$delim\E).)*+)/gs; # perl 5.10+
  s/\Q$escape$delim\E/$delim/g for @path;
  @path=grep(!/^$/, @path); # Drop meaningless (excess) deimiters (/foo//bar)

  # This block handles absolute and relative paths
  my $path_str='';
  if ($path_string =~ m%^/%) { # Absolute path
    $path_str=join("\0",@path);
  } else { # Relative path
    my $pwd=$state->{all_grp_paths_rev}->{$state->{path}->{id}};
    my @nwd=split("\0", $pwd);
    push @nwd, @path;
    $path_str=join("\0", @nwd);
  }

  # We should now have a NULL-separated, fully qualified path and
  # we just need to work on cleaning up things like "." and ".."
  # Squash single dots
  while ($path_str=~s/\0[.]\0|^[.]\0|\0[.]$/\0/) {}
  # Kill ".." and their parents
  while ($path_str=~s/[^\0]+\0+[.][.]//) {}
  $path_str=~s/\0\0+/\0/g; # squash any adjacent delimeters
  $path_str=~s/^\0+//; # squash any leading delimeters
  $path_str=~s/\0+$//; # squash any trailing delimeters

  return $path_str;
}

sub cli_cd_helper($$) {
  my $state=shift @_;
  my $path_str=shift @_;
  if (defined($state->{all_grp_paths_fwd}->{$path_str})) {
    $state->{oldpwd}=get_pwd();
    my $id=$state->{all_grp_paths_fwd}->{$path_str};
    $state->{path}->{id}=$id;
    return 0;
  } elsif ($path_str eq '') { # cd /
    $state->{oldpwd}=get_pwd();
    delete $state->{path};
    return 0;
  } else {
    print "Invalid path\n";
    return -1;
  }
}

sub cli_find($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  destroy_found();

  # Now do the Title search
  my $k=$state->{kdb};
  my $search_str = $params->{args}->[0];
  print "Searching for \"$search_str\" ...\n";

  # Make $search_str a case-insensitive regex
  my @letters=split(//, $search_str);
  foreach my $l (@letters) {
    if (uc($l) ne lc($l)) {
      $l='[' . uc($l) . lc($l) . ']';
    }
  }
  $search_str=join('', @letters);

  # Search entries by title, skipping the KeePassX /Backup group if it exists
  my $search_params = { 'title =~' => $search_str };
  my $backup_dir_normalized=normalize_path_string("/Backup"); # /Backup
  if (defined($state->{all_grp_paths_fwd}->{$backup_dir_normalized})) {
    $search_params->{'group_id !'} =
		$state->{all_grp_paths_fwd}->{$backup_dir_normalized};
  }
  my @e = $k->find_entries($search_params);

  if ( scalar(@e) < 1) {
    print "No matches.\n";
    return;
  }

  # If we get this far we have results to add to a new /_found
  my $found_group = $k->add_group({title => $FOUND_DIR}); # root level group
  my $found_gid = $found_group->{'id'};
  $k->unlock;
  my @matches=();
  FINDS: foreach my $ent (@e) {
    my %new_ent = %{$ent}; # Clone the entity
    $new_ent{id} = int(rand(1000000000000000)); # A random new id
    $new_ent{group} = $found_gid; # Place this entry clone into /_found
    # $new_ent{path} is _NOT_ a normal key for File::KeePass but this is
    # safe because we are adding it to entries in the /_found group which
    # will not be saved to a file.
    my $nulled_path=$state->{all_ent_paths_rev}->{$ent->{id}};
    $new_ent{path} = '/' . dirname(humanize_path($nulled_path)) . '/';
    $new_ent{full_path} = '/' . humanize_path($nulled_path);
    $k->add_entry(\%new_ent);
    push(@matches, \%new_ent);
  }
  $k->lock;

  # Because we added a new /_found we must refresh our $state paths
  refresh_state_all_paths();

  # Tell the user what we found
  print " - ".scalar(@matches)." matches found and placed into /$FOUND_DIR/\n";

  # If we only found one, ask the user if they want to see it
  if (scalar(@matches) == 1) {
    print "Would you like to show this entry? [y/N] ";
    my $key=get_single_key();
    print "\n";
    if (lc($key) eq 'y') {
      my $search_params = { 'group_id =' => $found_gid };
      my ($e,@empty) = $k->find_entries($search_params);
      my $full_path="/$FOUND_DIR/" . $e->{title};
      cli_show($self, { args => [ $full_path ] });
    }
  }
}

# Something is going wrong between KeePassX and File::KeePass related to
# the unknown values read/written by File::KeePass from/to files written
# by KeePassX. Commenting out line 378 of File/KeePass.pm is one fix,
# this prevents me from needing to do that by just removing the unknown
# values before saving. If there is a downside to this on the KeePassX
# side I've not found it yet. I do have an email out to Paul, the author
# of File::KeePass, requesting some assistance in grokking the problem.
#
# NOTE: I thought that this should not be needed for File::Keepass >= 0.3,
#       but on 2011-02-02 I discovered that creating new groups with
#       File::Keepass and not scrubbing on save created corrupt files:
#               "Group header offset is out of range" errors.
#       Sourceforge bug# 3187054 demonstrated the problem as well.
sub scrub_unknown_values_from_all_groups {
  our $state;
  # No need to do this with newer versions of File::KeePass (fixed in 2.01)
  if (version->parse($File::KeePass::VERSION) >= version->parse('2.03')) {
    return;
  }
  my $k=$state->{kdb};
  my @all_groups_flattened = $k->find_groups({});
  my @unkown_field_groups=();
  foreach my $g (@all_groups_flattened) {
    if (defined($g->{unknown})) {
      #warn "LHHD: " . &Dumper($g->{unknown}) . "\n";
      delete $g->{unknown};
      push @unkown_field_groups, $g->{title};
    }
  }
  my $count = scalar(@unkown_field_groups);
  if ($count > 0) {
    warn "Deleted unknown fields from these $count groups: " .
					join(", ", @unkown_field_groups) . "\n";
  }
}

sub deny_if_readonly {
  our %opts;
  if (defined($opts->{readonly}) && int($opts->{readonly})) {
    print "Function not available with --readonly set.\n";
    return 1;
  }
  return 0;
}

sub cli_save($) {
  my $self = shift @_;
  my $params = shift @_;

  if (deny_if_readonly()) { return; }

  our $state;
  if (! length($state->{kdb_file})) {
    print "Please use the saveas command for new files.\n";
    return;
  }

  # If the user has asked for a *.kdbx file, check the File::KeePass version
  if (version->parse($File::KeePass::VERSION) < version->parse('2.03')) {
    if ($state->{kdb_file} =~ m/\.kdbx$/i) {
      print "KeePass v2 (*.kdbx files) require File::KeePass >= v2.03\n";
      return;
    }
  }

  if (warn_if_file_changed()) {
    return;
  }

  # Check for a lock file that we did not place there
  my $lock_file = $state->{kdb_file} . '.lock'; # KeePassX style
  if (-f $lock_file && $state->{placed_lock_file} ne $lock_file) {
    my $bold="\e[1m";
    my $red="\e[31m";
    my $yellow="\e[33m";
    my $clear="\e[0m";
    print $bold . $yellow .
        "WARNING:" .
        $clear .
        $red .
               " A KeePassX-style lock file is in place for this file.\n" .
        "         It may be opened elsewhere. Save anyway? [y/N] " .
        $clear;
    my $key=get_single_key();
    print "\n";
    if (lc($key) ne 'y') {
      return;
    }
  }

  # If we got this far the user is OK with us locking the file even
  # if we had a contention.
  touch_file($lock_file);
  $state->{placed_lock_file} = $lock_file;

  # Scrub the data and write the file
  destroy_found();
  scrub_unknown_values_from_all_groups(); # TODO - remove later
  my $k=$state->{kdb};
  $k->unlock;
  my $master_pass=
	composite_master_pass($state->{get_master_passwd}(),$state->{key_file});
  $k->save_db($state->{kdb_file},$master_pass);
  $state->{kdb_has_changed}=0; # set our state to no change since last save
  $master_pass="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  print "Saved to $state->{kdb_file}\n";
  $k->lock;

  # Update the md5sum of the file after we just saved it
  my $file = $state->{kdb_file};
  $state->{kdb_file_md5} = Digest::file::digest_file_hex($file, "MD5");
}

# This subroutine handles the clipboard commands (xw, xu, xp, and xx)
sub cli_xN($$) {
  my $xNcmd = shift @_;
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  # If Clipboard is not avaiable we can't do this for the user
  if  (! $state->{OPTIONAL_PM}->{'Clipboard'}->{loaded}) {
    print "Error: $xNcmd requires the Clipboard and Capture::Tiny modules:\n" .
	" - http://search.cpan.org/~king/Clipboard/\n" .
	" - http://search.cpan.org/~dagolden/Capture-Tiny/\n" .
	"";
    if (defined($state->{OPTIONAL_PM}->{'Clipboard'}->{error})) {
      print "\nThere was an error loading the Clipboard module, as follows:\n" .
		$state->{OPTIONAL_PM}->{'Clipboard'}->{error} . "\n";
    }
    return;
  }

  # If we're clearing the clipboard, just do that and return immediately.
  if ($xNcmd eq 'xx') {
    Clipboard->copy('');
    print "Clipboard cleared.\n";
    return;
  }

  # Find the entry that the user wants to copy to the clipboard from.
  my $target = $params->{args}->[0];
  my $ent=find_target_entity_by_number_or_path($target);
  if (! defined($ent)) {
    print "Don't see an entry at path: $target\n";
    return -1;
  }

  # Switch over the xN commands and place the data into $to_copy
  my $to_copy = '';
  SWITCH: {
    $xNcmd eq 'xu' && do { $to_copy = $ent->{username}; last SWITCH; };
    $xNcmd eq 'xw' && do { $to_copy = $ent->{url}; last SWITCH; };
    $xNcmd eq 'xp' && do {
			$to_copy = $state->{kdb}->locked_entry_password($ent);
			last SWITCH; };
    warn "Error: cli_xN() does not know how to handle the $xNcmd command.";
    $to_copy = undef;
  }

  # Copy to the clipboard and tell the user what we did.
  my $cp_map = {
	'xu' => 'username',
	'xw' => 'url',
	'xp' => 'password',
	};
  if (defined($to_copy)) {
    Clipboard->copy($to_copy);
    print "Copied $cp_map->{$xNcmd} for \"$ent->{title}\" to the clipboard.\n";
  }

  return;
}

sub cli_rm($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if (deny_if_readonly() || warn_if_file_changed()) {
    return;
  }

  my $target = $params->{args}->[0];
  my $ent=find_target_entity_by_number_or_path($target);
  if (! defined($ent)) {
    print "Don't see an entry at path: $target\n";
    return -1;
  }

  my $ent_id=$ent->{id};
  $state->{kdb}->delete_entry({ id => $ent_id });
  $state->{kdb_has_changed}=1;
  RequestSaveOnDBChange();
}

sub validate_entry_number($$) {
  my $item_number=shift @_;
  my $path=shift @_;
  our $state;

  if (normalize_path_string($path) eq '') {
    print "Entries cannot exist in the root path (/).\n";
    return -1;
  }

  if ($item_number !~ m/^[0-9]+$/) {
    print "Invalid item number (must be an integer).\n";
    return -1;
  }

  my ($rGrps,$rEnts) = get_groups_and_entries($path);
  my $entry_max=scalar(@{$rEnts}) - 1;
  if ($item_number > $entry_max) {
    print "Invalid item number.  Valid entries are 0-$entry_max.\n";
    return -1;
  }
return 0;
}

# This routine takes one parameter that will be either a path
# to an entity or an entity number as shown my the ls command
# and will use $state information such as last_ls_path to
# return a reference to that entity in the $state-{kdb} database,
# if possible (valid input).
sub find_target_entity_by_number_or_path($) {
  my $target=shift @_;
  our $state;

  my $ent=undef; # hope to populate this in a second...

  # This section looks for an entity by an "ls" number
  if ($target =~ m/^[0-9]+$/) {
    my $path=$state->{last_ls_path};
    if (!length($path)) { $path=get_pwd(); }
    if (! validate_entry_number($target,$path)) {
      my ($rGrps,$rEnts) = get_groups_and_entries($path);
      $ent=$rEnts->[$target];
    }
  }

  # This section looks by a path name
  if (defined $state->{all_ent_paths_fwd}->{normalize_path_string($target)}) {
    my $entry_id=$state->{all_ent_paths_fwd}->{normalize_path_string($target)};
    $ent = $state->{kdb}->find_entry( {id=>$entry_id} );
  }

  return $ent;
}

sub cli_rename($$) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if (deny_if_readonly() || warn_if_file_changed()) {
    return;
  }

  my $target_dir = $params->{args}->[0];
  my $dir_normalized=normalize_path_string($target_dir);
  my $grp=undef;
  if (defined($state->{all_grp_paths_fwd}->{$dir_normalized})) {
    my $grp_id = $state->{all_grp_paths_fwd}->{$dir_normalized};
    $grp=$state->{kdb}->find_group( { id => $grp_id } );
  }
  if (! defined($grp)) {
    print "Unknown group: $target_dir\n";
    return -1;
  }

  print "Enter the groups new Title: ";
  my $new_title = ReadLine(0);
  chomp($new_title);
  if (length($new_title)) {
    $state->{kdb}->unlock;
    $grp->{title} = $new_title;
    $state->{kdb}->lock;
  }

  # Because we renamed a group we must refresh our $state paths
  refresh_state_all_paths();
  $state->{kdb_has_changed}=1;
  RequestSaveOnDBChange();
}

sub cli_mv($$) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if (deny_if_readonly() || warn_if_file_changed()) {
    return;
  }

  my $target_ent = $params->{args}->[0];
  my $ent=find_target_entity_by_number_or_path($target_ent);
  if (! defined($ent)) {
    print "Unknown entry: $target_ent\n";
    return -1;
  }

  my $target_dir = $params->{args}->[1];
  my $dir_normalized=normalize_path_string($target_dir);
  my $grp=undef;
  if (defined($state->{all_grp_paths_fwd}->{$dir_normalized})) {
    my $grp_id = $state->{all_grp_paths_fwd}->{$dir_normalized};
    $grp=$state->{kdb}->find_group( { id => $grp_id } );
  }
  if (! defined($grp)) {
    print "Unknown group: $target_dir\n";
    return -1;
  }

  # Verify no entry title conflict at the new location
  my $new_entry_path=$dir_normalized . "\0" . $ent->{title};
  if (defined($state->{all_ent_paths_fwd}->{$new_entry_path})) {
    print "There is already and entry named \"$ent->{title}\" there.\n";
  }

  # Unlock the kdb, clone the entry, remove its ID and set its new group,
  # add it to the kdb, delete the old entry, then lock the kdb...
  $state->{kdb}->unlock;
  my %ent_copy = %{$ent};
  delete $ent_copy{id};
  $ent_copy{group} = $grp;
  if ($state->{kdb}->add_entry(\%ent_copy)) {
    $state->{kdb}->delete_entry({ id=>$ent->{id} });
  }
  $state->{kdb}->lock;

  # Because we moved an entry we must refresh our $state paths
  refresh_state_all_paths();
  $state->{kdb_has_changed}=1;
  RequestSaveOnDBChange();
}

sub cli_show($$) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  # Users can provide a -f option to show the password. We use GetOptions
  # to parse this command line, and $target holds that target.
  my $target='';
  my %opts=();
  {
    local @ARGV = @{$params->{args}};
    my $result = &GetOptions(\%opts, 'f', 'a');
    if (scalar(@ARGV) != 1) {
      return -1;
    }
    $target = $ARGV[0];
  }

  my $ent=find_target_entity_by_number_or_path($target);
  if (! defined($ent)) {
    return -1;
  }

  print "\n";
  if (defined($ent->{path})) {
    print show_format("Path",$ent->{path}) . "\n";
  }
  # Unless -f is specified, we "hide" the password as red-on-red.
  my $password = $state->{kdb}->locked_entry_password($ent);
  if (! defined($opts{f})) {
    $password = colored(['red on_red'], $password);
  }
  print
	show_format("Title",$ent->{title}) . "\n" .
	show_format("Uname",$ent->{username}) . "\n" .
	show_format("Pass",$password) . "\n" .
	show_format("URL",$ent->{url}) . "\n" .
	show_format("Notes",$ent->{comment}) . "\n" .
	($DEBUG ? show_format("ID",$ent->{id}) . "\n" : '');
  if (defined($opts{a})) {
    print
	show_format("Icon#",$ent->{icon}) . "\n" .
	show_format("Creat",$ent->{created}) . "\n" .
	show_format("Modif",$ent->{modified}) . "\n";
  }
  print "\n";
  print &Dumper($ent) . "\n" if ($DEBUG > 2);
}

sub cli_edit($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if (deny_if_readonly() || warn_if_file_changed()) {
    return;
  }

  my $target = $params->{args}->[0];
  my $ent=find_target_entity_by_number_or_path($target);
  if (! defined($ent)) {
    print "Don't see an entry at path: $target\n";
    return -1;
  }

  # Need to unlock to make edits to the password
  $state->{kdb}->unlock;
  # Loop through the fields taking edits the user wants to make
  my @fields = get_entry_fields();
  my $had_changes=0;
  foreach my $input (@fields) {
    if ($input->{hide_entry}) {
      print $input->{txt} . ": ";
    } else {
      my $val = $ent->{$input->{key}};
      if ($val =~ m/\r|\n/) { $val = "\n$val\n"; }
      print $input->{txt} . " (\"".$val."\"): ";
    }
    if ($input->{genpasswd}) {
      print " "x25 . '("g" to generate a password)' . "\r";
    }
    if ($input->{hide_entry}) {
      ReadMode(2); # Hide typing
    }
    my $val = '';
    if ($input->{multiline}) {
      $val = new_edit_multiline_input($input);
    } else {
      $val = new_edit_single_line_input($input);
    }
    # If the field was not empty, change it to the new $val
    if (length($val)) {
      $ent->{$input->{key}} = $val;
      $had_changes=1;
    }
    ReadMode(0); # Return to normal
  }
  # Relock after editing is complete
  $state->{kdb}->lock;

  # If the use made changes, update modify time and prompt them to save
  if ($had_changes) {
    $ent->{modified} = $state->{kdb}->now;
    refresh_state_all_paths();
    $state->{kdb_has_changed}=1;
    RequestSaveOnDBChange();
  }

return 0;
}

# Single line input helper function for cli_new and cli_edit.
# Single line input helper function for cli_new and cli_edit.
sub new_edit_single_line_input($) {
  my $input = shift @_;
  my $val = ReadLine(0);
  if ($input->{hide_entry}) { print "\n"; }
  chomp $val;
  if ($input->{genpasswd} && $val eq 'g') {
    $val=generatePassword(20);
  } elsif (length($val) && $input->{double_entry_verify}) {
    print "Retype to verify: ";
    my $checkval = ReadLine(0);
    if ($input->{hide_entry}) { print "\n"; }
    chomp $checkval;
    if ($checkval ne $val) {
      print "Entries mismatched. Please try again.\n";
      redo;
    }
  }
  return $val;
}
# Multi-line input helper function for cli_new and cli_edit.
sub new_edit_multiline_input($) {
  my $input = shift @_;

  my $bold="\e[1m";
  my $red="\e[31m";
  my $yellow="\e[33m";
  my $clear="\e[0m";
  print "\n$yellow(end multi-line input with a single \".\" on a line)$clear\n";

  my $val = ''; my $unfinished = 1;
  while ($unfinished) {
    my $line = ReadLine(0);
    if ($line =~ m/^\.[\r\n]*$/) { # a lone "." ends our input
      $unfinished = 0;
    } else {
      $val .= $line;
      if ($val =~ m/^[\r\n]*$/) { $val = ''; $unfinished = 0; }
    }
  }
  chomp($val); # Remove extra line at the end
  return $val;
}

# Formats an entry for display for cli_show()
sub show_format($$) {
  my $title=shift @_;
  my $value=shift @_;
  my $val=$value;
  if ($val =~ m/\n/) {
    my @val_lines=split(/\n/, $val);
    $val=join("\n" . " "x(5+2), @val_lines);
  }
  return sprintf("%5s: %s", $title,$val);
}

# Formats a statistic display for cli_stats()
sub stats_print($) {
  my $stats_r = shift @_;

  my $max_key_len = 0;
  my $max_val_len = 0;
  foreach my $k (keys(%{$stats_r})) {
    if (length($k) > $max_key_len) { $max_key_len = length($k); }
  }
  foreach my $k (values(%{$stats_r})) {
    if (length($k) > $max_val_len) { $max_val_len = length($k); }
  }
  my $sprintf_format = "  - %$max_key_len" . "s: %$max_val_len" . "d\n";
  my $t='';
  foreach my $stat_key (sort {$a <=> $b} keys %{$stats_r}) {
    $t .= sprintf($sprintf_format, $stat_key, $stats_r->{$stat_key});
  }
  return $t;
}

sub get_entry_fields {
  my @fields = (
	{ key=>'title', txt=>'Title' },
	{ key=>'username', txt=>'Username' },
	{ key=>'password', txt=>'Password',
		hide_entry => 1, double_entry_verify => 1, genpasswd => 1 },
	{ key=>'url', txt=>'URL' },
	{ key=>'comment', txt=>'Notes/Comments', 'multiline' => 1 },
	);
  return @fields;
}

sub cli_icons($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  print "Change icons on Groups or Entries (g/e/Cancel)? ";
  my $groups_or_entries=lc(get_single_key());
  print "\n";
  if ($groups_or_entries !~ m/^[ge]$/) { return; }

  print "Change icons Here, Below here, or Globally (h/b/g/Cancel)? ";
  my $glob_or_rel=lc(get_single_key());
  print "\n";
  if ($glob_or_rel !~ m/^[hgb]$/) { return; }

  print "What would you line the new icon to be (0-64/Cancel)? ";
  my $val = ReadLine(0);
  chomp($val);
  if ($val !~ m/^[0-9]+$/ || $val < 0 || $val > 64) {
    print "Invalid icon number.\n";
    return;
  }

  # This code fills @{$groups} or @{$entries} with the items that the
  # user wants to change the icons on.
  my ($groups,$entries) = ([],[]);
  if ($glob_or_rel eq 'h') { # "Here" is easy -- we have a function for that.
    ($groups,$entries) = get_current_groups_and_entries();
    if ($groups_or_entries eq 'e') {
      $groups = [];
    } else {
      $entries = [];
    }
  } else {
    if ($glob_or_rel eq 'g') { # Globally is easy, it's all groups
      my $k=$state->{kdb};
      @{$groups} = $k->find_groups({});
    } elsif ($glob_or_rel eq 'b') {
      my $id=$state->{path}->{id};
      @{$groups} = all_child_groups_flattened($id); # *only child groups*
    } else {
      warn "WHAT? Should never get to this piece of code!\n";
    }
    # If the user wanted to operate on entries, collect all the entries
    # in the @{$groups} and then empty @{$groups}.
    if ($groups_or_entries eq 'e') {
      foreach my $group (@{$groups}) {
        if (defined($group->{entries})) {
          push @{$entries}, @{$group->{entries}};
        }
      }
      $groups = [];
    }
  }

  # Change the items, recording the number of changes.
  my $items_changed=0;
  foreach my $item (@{$groups}, @{$entries}) {
    $item->{icon} = $val;
    $items_changed++;
  }

  # Tell the user what we did.
  print "The icon value was set to $val on $items_changed records.\n";

  # If we changed anything, ask the user if they want to save
  if ($items_changed > 0) {
    $state->{kdb_has_changed}=1;
    RequestSaveOnDBChange();
  }
  return 0;
}

sub cli_new($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if (deny_if_readonly() || warn_if_file_changed()) {
    return;
  }

  my $pwd=get_pwd();
  if ($pwd =~ m/^\/+$/) {
    print "Entries cannot be made in this path ($pwd).\n";
    return -1;
  }

  print "Adding new entry to \"$pwd\"\n";

  # Grab the entries at this $id (pwd) so we can check for conflicts
  my $k=$state->{kdb};
  my $id=$state->{path}->{id};
  my ($this_grp,@trash) = $k->find_groups({id=>$id});
  my @entries = $k->find_entries({group_id => $id});

  my $new_entry = {
    'group' => $id,
  };

  my @fields = get_entry_fields();
  foreach my $input (@fields) {
    if ($input->{genpasswd}) {
      print " "x25 . '("g" to generate a password)' . "\r";
    }
    print $input->{txt} . ": ";
    if ($input->{hide_entry}) {
      ReadMode(2); # Hide typing
    }
    my $val = '';
    if ($input->{multiline}) {
      $val = new_edit_multiline_input($input);
    } else {
      $val = new_edit_single_line_input($input);
    }
    # If the user gave us an empty title, abort the new entry
    if ($input->{key} eq 'title' && length($val) == 0) {
      return;
    }
    $new_entry->{$input->{key}} = $val;
    ReadMode(0); # Return to normal
  }
  $new_entry->{icon} = $DEFAULT_ENTRY_ICON;

  $k->unlock;
  my $new_entry_ref = $k->add_entry($new_entry);
  $k->lock;
  if ($new_entry_ref->{id}) {
    refresh_state_all_paths();
    $state->{kdb_has_changed}=1;
    RequestSaveOnDBChange();
  } else {
    print "Failed to add new entry.\n";
  }
  return 0;
}

sub cli_import($$) {
  my $file=shift @_;
  my $new_group=shift @_;
  my $key_file=shift @_;
  our $state;

  if (deny_if_readonly()) { return; }

  # If the user gave us a bogus file there's nothing to do
  if (! -f ($file)) {
    print "File does not exist: $file\n";
    return -1;
  }
  # If the $new_group path is relative, make it absolute
  if ($new_group !~ m/^\//) {
    $new_group = get_pwd() . "/$new_group";
  }
  # We won't import into an existing group
  my $full_path=normalize_path_string($new_group);
  if (defined($state->{all_grp_paths_fwd}->{$full_path})) {
    print "You must specify a _new_ group to import into.\n";
    return -1;
  }
  # Make sure the new group's parent exists
  my ($grp_path,$grp_name)=normalize_and_split_raw_path($new_group);
  if ($grp_path != '' && ! defined($state->{all_grp_paths_fwd}->{$grp_path})) {
    print "Path does not exist: /" . humanize_path($grp_path) . "\n";
    return -1;
  }
  # Set the $parent_group value appropriately
  my $parent_group = undef; # Root by default
  if (length($grp_path)) {
    $parent_group = $state->{all_grp_paths_fwd}->{$grp_path};
  }
  # Ask the user for the master password and then open the kdb
  my $master_pass=GetMasterPasswd();
  my $iKDB = File::KeePass->new;
  if (! eval { $iKDB->load_db($file,
			composite_master_pass($master_pass, $key_file)) }) {
    print "Couldn't load the file $file: $@\n";
    return -1;
  }
  # Add the new group, to its parent or to root if $parent_group==undef
  my $k=$state->{kdb};
  my $new_group=$k->add_group({
	title => $grp_name,
	group => $parent_group,
	});
  # Copy the $iKDB into our $k at $new_group
  $iKDB->unlock();
  $k->unlock();
  my @root_groups = $iKDB->find_groups({level=>0});
  foreach my $i_root_grp (@root_groups) {
    copy_kdb_group_tree($k,$i_root_grp,$new_group);
  }
  $k->lock();
  $iKDB->lock();
  $iKDB=undef;
  # Refresh all paths and mark state as changed
  refresh_state_all_paths();
  $state->{kdb_has_changed}=1;
  RequestSaveOnDBChange();
}

sub cli_export($$) {
  my $file=shift @_;
  my $key_file=shift @_;
  our $state;

  # Warn is we are being asked to overwrite a file
  if (-e $file) {
    print "WARNING: $file already exists.\n" .
		"Overwrite it? [y/N] ";
    my $key=get_single_key();
    print "\n";
    if (lc($key) ne 'y') {
      return -1;
    }
  }

  # Get the master password for the exported file
  my $master_pass=GetMasterPasswd();
  if (length($master_pass) == 0) {
    print "For your safety, empty passwords are not allowed...\n";
    return;
  }
  print "Retype to verify: ";
  ReadMode('noecho');
  my $checkval = ReadLine(0);
  ReadMode('normal');
  chomp $checkval;
  print "\n";
  if ($master_pass ne $checkval) {
    print "Passwords did not match...\n";
    return;
  }

  # Build the new kdb in RAM
  my $k=$state->{kdb};
  my $new_kdb=new File::KeePass;
  $k->unlock; # Required so that we can copy the passwords
  if (get_pwd() ne '/') {
    # Grab the root group's $id at our pwd
    my $pwd_group_id=$state->{path}->{id};
    my ($root_grp,@trash) = $k->find_groups({id=>$pwd_group_id});
    copy_kdb_group_tree($new_kdb,$root_grp,undef);
  } else {
    # Put all of the root groups into the new file (entire file copy)
    my @root_groups = $k->find_groups({level=>0});
    foreach my $root_grp (@root_groups) {
      copy_kdb_group_tree($new_kdb,$root_grp,undef);
    }
  }
  $k->lock;
  $new_kdb->unlock;
  my $new_db_bin =
		$new_kdb->gen_db(composite_master_pass($master_pass,$key_file));
  $new_kdb->lock;

  # Test parsing the kdb from RAM (we'll most likely die if this fails)
  my $new_db=new File::KeePass;
  $new_db->parse_db($new_db_bin,composite_master_pass($master_pass,$key_file));

  # Now write the new kdb to disk
  my $fh=new FileHandle;
  if (open($fh,'>',$file)) {
    print $fh $new_db_bin;
    close $fh;
    print "Exported to $file\n";
  } else {
    print "Could not open \"$file\" for writing.\n";
  }

  return 0;
}

# A helper function for cli_export() and cli_import(). It takes a kdb object,
# a group as a starting point to copy from, and optionally a parent_group to
# copy to. It copies everything from the source group's root downward. In our
# use cases, the _target_ $kdb object passed in here is typically a different
# one than the _source_ $group is from.
sub copy_kdb_group_tree($$$) {
  my $kdb=shift @_;
  my $group=shift @_;
  my $parent_group=shift @_ || undef; # When undef, it writes to the root

  # Add the new group, to it's parent or root if $parent_group==undef
  my $new_group=$kdb->add_group({
	title => $group->{title},
	icon => $group->{icon},
	id => $group->{id},
	group => $parent_group,
	});

  # Add the new_group's entries
  if (ref($group->{entries}) eq 'ARRAY') {
    foreach my $entry (@{$group->{entries}}) {
      $entry->{group} = $new_group;
      $kdb->add_entry($entry);
    }
  }

  # Add the new_group's child groups
  if (ref($group->{groups}) eq 'ARRAY') {
    foreach my $child_grp (@{$group->{groups}}) {
      copy_kdb_group_tree($kdb,$child_grp,$new_group);
    }
  }
}

sub cli_saveas($) {
  my $file=shift @_;
  my $key_file=shift @_;
  our $state;

  # If the user has asked for a *.kdbx file, check the File::KeePass version
  if (version->parse($File::KeePass::VERSION) < version->parse('2.03')) {
    if ($file =~ m/\.kdbx$/i) {
      print "KeePass v2 (*.kdbx files) require File::KeePass >= v2.03\n";
      return;
    }
  }

  my $master_pass=GetMasterPasswd();
  print "Retype to verify: ";
  ReadMode('noecho');
  my $checkval = ReadLine(0);
  ReadMode('normal');
  chomp $checkval;
  print "\n";
  if ($master_pass ne $checkval) {
    print "Passwords did not match...\n";
    return;
  }

  destroy_found();
  scrub_unknown_values_from_all_groups(); # TODO - remove later
  $state->{kdb}->unlock;
  $state->{kdb}->save_db($file,composite_master_pass($master_pass,$key_file));
  $state->{kdb}->lock;

  $state->{kdb}= File::KeePass->new;
  if (! eval { $state->{kdb}->load_db($file,
			composite_master_pass($master_pass,$key_file)) }) {
    die "Couldn't load the file $file: $@";
  }
  $state->{kdb_has_changed}=0;
  $state->{kdb_file} = $file;
  $state->{key_file} = $key_file;
  $state->{put_master_passwd}($master_pass);
  $master_pass="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  return 0;
}

# This routine takes a raw (directly from user input) path string
# and "normalizes" it (converts it to NULL-separated w/out escapes)
# and splits it into its dirname and basename components.
sub normalize_and_split_raw_path($) {
  my $raw_pathstr=shift @_;

  my $path=normalize_path_string($raw_pathstr);

  my $basename='';
  if ($path =~ m/\0/) {			# case of at least one path delimeter
    $path =~ s/\0([^\0]+)$//;
    $basename=$1;
  } elsif ($raw_pathstr =~ m/^\//) {	# case of simple "/foo" (no subdir)
    $basename=$path;
    $path='';
  } else {				# case of simple "foo" (no path delims)
    $path = normalize_path_string(get_pwd());
    $basename=$raw_pathstr;
  }
return($path,$basename);
}

sub cli_rmdir($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if (deny_if_readonly() || warn_if_file_changed()) {
    return;
  }

  my $raw_pathstr=$params->{'args'}->[0];
  my ($path,$grp_name) = normalize_and_split_raw_path($raw_pathstr);

  # Make sure the group exists.
  my $grp_path="$path\0$grp_name";
  $grp_path=~s/^\0+//;
  if (! defined($state->{all_grp_paths_fwd}->{$grp_path})) {
    print "Path does not exist: /" . humanize_path($grp_path) . "\n";
    return -1;
  }

  my $group_id = $state->{all_grp_paths_fwd}->{$grp_path};
  my $group = $state->{kdb}->find_group({ id => $group_id });
  my $entry_cnt=0;
  if (defined($group->{entries})) {
    $entry_cnt=
	scalar(grep(m/^\Q$grp_path\E\0/,keys %{$state->{all_ent_paths_fwd}}));
  }
  my $group_cnt=0;
  if (defined($group->{entries})) {
    $group_cnt=
	scalar(grep(m/^\Q$grp_path\E\0/,keys %{$state->{all_grp_paths_fwd}}));
  }
  my $child_cnt=$entry_cnt + $group_cnt;
  if ( $child_cnt > 0) {
    print "WARNING: This group has $child_cnt child groups and/or entries.\n" .
	"Really remove it!? [y/N] ";
    my $key=get_single_key();
    print "\n";
    if (lc($key) ne 'y') {
      return -1;
    }
  }
  my $deleted_group = $state->{kdb}->delete_group({ id => $group_id });

  # Because we removed a group we need to refresh our state paths
  refresh_state_all_paths();
  $state->{kdb_has_changed}=1;
  RequestSaveOnDBChange();
  return 0;
}

sub cli_mkdir($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if (deny_if_readonly() || warn_if_file_changed()) {
    return;
  }

  my $raw_pathstr = $params->{args}->[0];
  my ($path,$newdir) = normalize_and_split_raw_path($raw_pathstr);

  # Make sure the group doesn't already exist.
  my $newdir_path="$path\0$newdir";
  $newdir_path=~s/^\0+//;
  if (defined($state->{all_grp_paths_fwd}->{$newdir_path})) {
    print "Path already exists: /" . humanize_path($newdir_path) . "\n";
    return -1;
  }

  # Create the group
  my $group='';
  if ($path eq '') {
    $group = $state->{kdb}->add_group({
        title => $newdir,
	icon => $DEfAULT_GROUP_ICON,
    }); # root level group
  } elsif (defined($state->{all_grp_paths_fwd}->{$path})) {
    my $group_id=$state->{all_grp_paths_fwd}->{$path};
    $group = $state->{kdb}->add_group({
		title => $newdir,
		group => $group_id,
		icon => $DEfAULT_GROUP_ICON,
	});
  } else {
    print "Cannot make directory at path " . humanize_path($path) . "\n";
    return -1;
  }

  # Because we created a new group we need to refresh ours state paths
  refresh_state_all_paths();
  $state->{kdb_has_changed}=1;
  RequestSaveOnDBChange();
  return 0;
}

sub humanize_path($) {
  my $path=shift @_;
  $path =~ s/\//\\\//g;
  $path =~ s/\0/\//g;
  return $path;
}

sub cli_open($) {
  my $path=shift @_;
  my $key=shift @_;
  our $state;

  # If cli_close() does not return 0 the user decided not to close the file
  if (cli_close() != 0) {
    return -1;
  }

  if ( -f $path ) {
    my $err = open_kdb($path, $key);
    if (length($err)) {
      print "Error opening file: $err\n";
    }
  } else {
    print "Cannot open: $path\n";
  }
}

# Get a single keypress from the user
sub get_single_key {
  my $key='';
  ReadMode('raw'); # Turn off controls keys
  while (not defined ($key = ReadKey(-1))) {
    # No key yet
  }
  ReadMode('restore');
return $key;
}

sub cli_close {
  our $state;

  if ($state->{kdb_has_changed}) {
    print "WARNING: The database has changed and was not saved.\n" .
	"Really close it? [y/N] ";
    my $key=get_single_key();
    print "\n";
    if (lc($key) ne 'y') {
      return -1;
    }
  }

  $state->{'kdb'}->clear();
  new_kdb($state);
  return 0;
}

# This sets $state to a brand new, KeePassX-style, empty, unsaved database
sub new_kdb($) {
  my $state=shift @_;
  $state->{kdb_has_changed}=0;
  $state->{'kdb'} = File::KeePass->new;
  # To be compatible with KeePassX
  $state->{'kdb'}->add_group({ title => 'eMail' });
  $state->{'kdb'}->add_group({ title => 'Internet' });
  refresh_state_all_paths();
  if (-f $state->{placed_lock_file}) { unlink($state->{placed_lock_file}); }
  delete($state->{placed_lock_file});
  delete($state->{kdb_file});
  delete($state->{key_file});
  delete($state->{master_pass});
  cli_cd($term, {'args' => ["/"]});
}

sub cli_ls($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  my $path=$params->{'args'}->[0];

  # If we were given a path, use cli_cd() to go there temporarily...
  my $old_path='';
  if (length($path)) {
    $old_path=get_pwd();
    if (cli_cd($term, {'args' => [$path]})) {
      return -1; # If cli_cd() returned non-zero it failed
    }
  }

  # List the pwd
  $state->{last_ls_path} = get_pwd();
  my ($rGrps,$rEnts) = get_current_groups_and_entries();
  if (scalar(@{$rGrps}) > 0) {
    print "=== Groups ===\n";
    print join("\n", @{get_human_group_list($rGrps)}) . "\n";
  }
  if (scalar(@{$rEnts}) > 0) {
    print "=== Entries ===\n";
    print join("\n", @{get_human_entry_list($rEnts)}) . "\n";
  }

  # If we temporarily cd'ed, cd back.
  if (length($old_path)) {
    cli_cd($term, {'args' => [$old_path]});
  }

  return 0;
}

# Helper function for cli_ls()
sub get_human_group_list($) {
  my $rGroup=shift @_;
  my @list=();
  foreach my $grp (@{$rGroup}) {
    #push (@list, sprintf("%15d %s/", $grp->{id}, $grp->{title}));
    push (@list, "$grp->{title}/");
    push (@list, &Dumper($grp)) if ($DEBUG > 2);
  }
  return \@list;
}

# Helper function for cli_ls()
sub get_human_entry_list($) {
  my $rEntries=shift @_;
  my @list=();
  my $i=0;
  my $d_len=int((scalar(@{$rEntries}) - 1) / 10) + 1;
  foreach my $ent (@{$rEntries}) {
    my $url=$ent->{url};
    $url=~s/^https?:\/\///i;
    $url=~s/\/+$//;
    push (@list, sprintf("%".$d_len."d. %-40.40s %30.30s",
						$i, $ent->{title}, $url));
    $i++;
  }
  return \@list;
}

# Routine to hook into Term::ShellUI's exit on Ctrl-D functionality
sub eof_exit_hook {
  our $state;
  # We need a newline if cli_quit() will talk tothe user about saving
  if ($state->{kdb_has_changed}) { print "\n"; }
  # cli_quit() will handle user interaction and return a value for
  # the exit_hook of Term::ShellUI.
  return cli_quit($state->{term},undef);
}

sub cli_quit($$) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if ($state->{kdb_has_changed}) {
    print "WARNING: The database has changed and was not saved.\n" .
	"Really quit? [y/N] ";
    my $key=get_single_key();
    if (lc($key) ne 'y') {
      print "\n";
      return -1; # It is not OK to quit
    }
  }

  if (-f $state->{placed_lock_file}) { unlink($state->{placed_lock_file}); }
  delete($state->{placed_lock_file});
  $self->exit_requested(1);
  return 0; # It's OK to quit
}

# Function to nag the user about saving each time the DB is modified
sub RequestSaveOnDBChange {
  our $state;

  # If the db hasn't changed don't bother the user
  if (! $state->{kdb_has_changed}) {
    return -1;
  }

  # If this is a newly created file we don't bother the user with
  # asking to save after every change.
  if (! length($state->{kdb_file})) {
    return -1;
  }

  print "Database was modified. Do you want to save it now? [y/N]: ";
  my $key=get_single_key();
  print "\n";
  if (lc($key) ne 'y') {
    return;
  }

  # Calling cli_save() should be silent and safe at this point.
  return cli_save(undef);
}

sub GetMasterPasswd {
  print "Please provide the master password: ";
  ReadMode('noecho');
  my $master_pass = ReadLine(0);
  chomp $master_pass;
  ReadMode('normal');
  print "\n";
  return $master_pass;
}

sub MyGetOpts {
  my %opts=();
  my $result = &GetOptions(\%opts, "kdb=s", "key=s", "histfile=s",
						"help", "h", "readonly");

  # If the user asked for help or GetOptions complained, give help and exit
  if ($opts{help} || $opts{h} || (! int($result))) {
    print GetUsageMessage();
    exit;
  }

  # Allow the user to override the history file
  if (defined($opts{histfile}) && length($opts{histfile})) {
    our $HISTORY_FILE = $opts{histfile};
  } else {
    our $HISTORY_FILE = "~/.$APP_NAME-history";
  }

  my @errs=();
  if ((length($opts{kdb}) && (! -e $opts{kdb}))) {
    push @errs, "for option --kdb=<file.kbd>, the file must exist.";
  }

  if ((length($opts{key}) && (! -e $opts{key}))) {
    push @errs, "for option --key=<file.key>, the file must exist.";
  }

  if (scalar(@errs)) {
    warn "There were errors:\n" .
	"  " . join("\n  ", @errs) . "\n\n";
    die &GetUsageMessage();
  }

  return \%opts;
}

sub GetUsageMessage {
  my $t="Usage: $APP_NAME [--kdb=<file.kdb>] [--key=<file.key>]\n" .
  "\n" .
  "    --help\tThis message.\n" .
  "    --kdb\tOptional KeePass database file to open (must exist).\n" .
  "    --key\tOptional KeePass key file (must exist).\n" .
  "    --histfile\tSpecify your history file (or perhaps /dev/null).\n" .
  "    --readonly\tRun in read-only mode; no changes will be allowed.\n" .
  "\n" .
  "Run kpcli with no options and type 'help' at its command prompt to learn\n" .
  "about kpcli's commands.\n";
  "\n";
  return $t;
}

# Because Term::ShellUI has a fixed width (%20s) for the command length
# and we don't need nearly that much, we had to implement our own help
# function instead of using the built-in help_call() method.
sub my_help_call($) {
  my $term = shift @_;
  # @_ now holds: [Term::ShellUI->{commands}, <optional: specific command>]
  # If the user is asking for detailed help on a specific command, do that
  if (scalar(@_) > 1) {
    $term->help_call(undef, @_);
    return;
  }
  # If no specific command was requested, show the command summaries
  my $help = $term->get_all_cmd_summaries($term->commands());
  $help =~ s/^ {12}//gm; # Trim some leading spaces off of each line of output
  print $help;
  print "\n" .
	"Type \"help <command>\" for more detailed help on a command.\n";
  return 0;
}

########################################################################
# Command Completion Routines ##########################################
########################################################################

sub complete_groups {
  my $self = shift;
  my $cmpl = shift;
  our $state;

  # Place the string (token) that the user is trying to complete into $path.
  my $path = $cmpl->{tokens}->[$cmpl->{tokno}];
  # If the cursor isn't at the end of the sting, chop $path to that length.
  if (length($path) > $cmpl->{tokoff}) {
    $path = substr($path, 0, $cmpl->{tokoff});
  }

  my $srch_path=normalize_path_string($path);
  my @possibles = ();
  # If the path ends in a "/" (a directory) then we are looking for subirs,
  # else we are just looking to tab-complete a partial dir-name at this level.
  # Used only for /<tab> (the root dir is a special case)
  if ($srch_path =~ m/^$|^[.]$/) {
    @possibles = grep(/^[^\0]+$/,
				sort keys %{$state->{all_grp_paths_fwd}});
  # Used only for /..any/thing../<tab> (non-root directories)
  } elsif (defined($state->{all_grp_paths_fwd}->{$srch_path})) {
    # If the user is sitting on a dir without the trailing /, return that
    # now as the only option (/dir1/dir2<tab>). We do this because the
    # code later does not handle this case well at all. We do, however,
    # have to not do this for things like "ls <tab>" which is why we test
    # for length($path).
    if (length($path) && $path !~ m/\/$/) {
      $self->suppress_completion_append_character();
      return [ $cmpl->{str} . "/" ];
    }
    @possibles = grep(/^\Q$srch_path\E\0[^\0]+$/,
				sort keys %{$state->{all_grp_paths_fwd}});
  # Used for /../any/thing../foo<tab>
  } else {
    @possibles = grep(/^\Q$srch_path\E[^\0]*$/,
				sort keys %{$state->{all_grp_paths_fwd}});
  }

  # Loop over the possibilites doing required magic...
  my @results=();
  foreach my $opt (@possibles) {
    $opt=humanize_path($opt);
    if ($path =~ m/^(\/+)/) {	# Absolute path (easy case!)
      $opt=$1.$opt;
    } else {			# Path relative to pwd
      my $user_new_path=get_pwd() . "/" . $path;
      my $new_dir=normalize_path_string($user_new_path);
      # If the user's input does not resolve to a fully qualified
      # path then we need to pop off the last bit to get to that.
      if (! defined($state->{all_grp_paths_fwd}->{$new_dir})) {
        my @path=split(/\0/, $new_dir); pop @path;
        $new_dir = join("\0", @path);
      }
      $new_dir = humanize_path($new_dir);
      # Dirname requires "../." (Trailing dot) to give ".." in those cases!
      my $dirname_path=$path;
      if ($path =~ m/\/$/) { $dirname_path .= "."; }
      my $path_to_put_back=dirname($dirname_path) . "/";
      if ($new_dir eq '') {	# All the way at the root level
        $opt = $path_to_put_back . $opt;
      } else {			# Some non-root level (deeper)
        $opt=~s/^$new_dir\//$path_to_put_back/;
      }
      # Lop the leading "./" off the head if it was not user supplied
      if ($path !~ m/^[.]\// && $opt =~ m/^[.]\//) { $opt =~ s/^[.]\///; }
      # If the user did supply a leading "./" and we missed it, add it
      if ($path =~ m/^[.]\// && $opt !~ m/^[.]\//) { $opt = "./$opt"; }
    }
    push @results, "$opt/";
  }

  # Foreach possibility, we have to strip off the parts that are already
  # completed and then prepend the part that is looking to be completed,
  # from $cmpl->{str}.
  my @completions = ();
  foreach my $possibility (@results) {
    $possibility = normalize_path_string($possibility);
    $possibility =~ s/^\Q$srch_path\E\0?//;
    if (length($possibility)) {
      $possibility = $cmpl->{str} . humanize_path($possibility);
      if ($possibility !~ m/\/$/) { $possibility .= '/'; }
      push @completions, $possibility;
    }
  }

  # If we are about to return only one completion result, we need to first
  # test to see if any other subdirs are below it and, if so, suppress the
  # completion append character so that the user can keep tab completing
  # into lower level directories.
  if (scalar(@completions) == 1) {
    my @all_subdirs = grep(/^\Q$srch_path\E[^\0]*(\0[^\0]+)?/,
				sort keys %{$state->{all_grp_paths_fwd}});
    if (scalar(@all_subdirs) > 0) {
      $self->suppress_completion_append_character();
    }
  }

  return \@completions;
}

sub complete_entries {
  my $self = shift;
  my $cmpl = shift;
  our $state;

  # Place the string (token) that the user is trying to complete into $path.
  my $path = $cmpl->{tokens}->[$cmpl->{tokno}];
  # If the cursor isn't at the end of the sting, chop $path to that length.
  if (length($path) > $cmpl->{tokoff}) {
    $path = substr($path, 0, $cmpl->{tokoff});
  }

  my $srch_path=normalize_path_string($path);
  my @entries = grep(/^\Q$srch_path\E\0?[^\0]*$/,
				sort keys %{$state->{all_ent_paths_fwd}});
  # User can tab exactly at a directory level and with or without the
  # trailing slash, and so we need to normalize that, always ensuring that
  # the slash is inserted. We do that by setting the dir_level_sep here
  # and always removing any trailing slash sent in below (\0 on srch_path).
  # We do, however, have to not do this for things like "show <tab>" which
  # is why we test for length($path).
  my $dir_level_sep = '';
  if (defined($state->{all_grp_paths_fwd}->{$srch_path}) &&
				length($path) && $path !~ m/\/$/) {
    $dir_level_sep = '/';
  }
  # Foreach possibility, we have to strip off the parts that are already
  # completed and then prepend the part that is looking to be completed
  # by Term::ShellUI, from $cmpl->{str}.
  my @completions = ();
  foreach my $possibility (@entries) {
    $possibility =~ s/^\Q$srch_path\E\0?//;
    if (length($possibility)) {
      $possibility = $cmpl->{str} .$dir_level_sep. humanize_path($possibility);
      push @completions, $possibility;
    }
  }

  return \@completions;
}

sub complete_groups_and_entries {
  my $self = shift;
  my $cmpl = shift;

  my $groups=complete_groups($self,$cmpl);
  my $entries=complete_entries($self,$cmpl);

  # Merge and sort the groups and entries
  my @completions = sort (@{$groups}, @{$entries});
  return \@completions;
}

########################################################################
# Rijndael encrypt/decrypt routines - borrowed from File::KeePass ######
########################################################################
sub decrypt_rijndael_cbc {
    my ($buffer, $key, $enc_iv) = @_;
    my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($enc_iv);
    $buffer = $cipher->decrypt($buffer);
    my $extra = ord(substr $buffer, -1, 1);
    substr($buffer, length($buffer) - $extra, $extra, '');
    return $buffer;
}
sub encrypt_rijndael_cbc {
    my ($buffer, $key, $enc_iv) = @_;
    my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($enc_iv);
    my $extra = (16 - length($buffer) % 16) || 16; # pad so we can trim
    $buffer .= chr($extra) for 1 .. $extra;
    return $cipher->encrypt($buffer);
}
sub composite_master_pass($$) {
  my ($pass, $key_file) = @_;

  # composite password in case of key file
  if (defined $key_file and length($key_file) and -f $key_file) {
    # KeePass v2.03 and higher has native key file support, and so we
    # use that if we have it.
    if (version->parse($File::KeePass::VERSION) >= version->parse('2.03')) {
      return [$pass, $key_file];
    }
    # TODO - at some point, when File::KeePass v2.03 is very mainstream,
    # the code to the end of this if block should be removed. It allowed
    # support for key files for *.kdb files before File::KeePass supported
    # that natively. File::KeePass now also supports that for *.kdbx.
    open(my $fh,'<',$key_file) || die "Couldn't open key file $key_file: $!\n";
    my $size = -s $key_file;
    read($fh, my $buffer, $size);
    close $fh;
    if (length($buffer) != $size) {
      die "Couldn't read entire key file contents of $key_file.\n";
    }

    $pass = substr(sha256($pass),0,32);
    if ($size == 32) {
      $pass .= $buffer;
    } elsif ($size == 64) {
      for (my $i = 0; $i < 64; $i += 2) {
        $pass .= chr(hex(substr($buffer,$i,2)));
      }
    } else {
      $pass .= substr(sha256($buffer),0,32);
    }
  }

  return $pass;
}
sub put_master_passwd($) {
  my $master_pass = shift @_;
  our $state;
  $state->{'master_pass_key'}='';
  $state->{'master_pass_key'} .= chr(int(255 * rand())) for 1..16;
  $state->{'master_pass_enc_iv'}='';
  $state->{'master_pass_enc_iv'} .= chr(int(255 * rand())) for 1..16;
  $master_pass='CLEAR:' . $master_pass;
  $state->{'master_pass'}=encrypt_rijndael_cbc($master_pass,
		$state->{'master_pass_key'}, $state->{'master_pass_enc_iv'});
  return 0;
}
sub get_master_passwd() {
  our $state;
  my $master_pass=decrypt_rijndael_cbc($state->{master_pass},
		$state->{'master_pass_key'}, $state->{'master_pass_enc_iv'});
  if ($master_pass=~s/^CLEAR://) {
    return $master_pass;
  } else {
    die "Failed to properly decrypt my copy of the master password.\n";
  }
}

# This routine checks to see if the file has changed on disk and warns if so
sub warn_if_file_changed {
  our $state;

  my $file = $state->{kdb_file};
  if (! length($file)) { return 0; } # If no file was opened, don't warn
  my $file_md5 = Digest::file::digest_file_hex($file, "MD5");
  if ($state->{kdb_file_md5} ne $file_md5) {
    my $bold="\e[1m";
    my $red="\e[31m";
    my $yellow="\e[33m";
    my $clear="\e[0m";
    print $bold . $yellow .
        "WARNING:" .
        $clear .
        $red .
               " The file has changed on disk since kpcli opened it!\n" .
        "         It may be opened elsewhere. Continue anyway? [y/N] " .
        $clear;
    my $key=get_single_key();
    print "\n";
    if (lc($key) ne 'y') {
      return -1;
    }
  }

  return 0;
}

sub generatePassword {
   my $length = shift;
   my @normal_chars=('a'..'z','A'..'Z',0..9);
   my @special_chars=qw(_);
   my $charset = join('', (@normal_chars,@special_chars));
   # Generate the password
   my $password = '';
   while (length($password) < $length) {
     $password .= substr($charset, (int(rand(length($charset)))), 1);
   }
   # Make sure that at least one special character appears
   my $sccc=join('', @special_chars);
   if ($password !~ m/[\Q$sccc\E]/) {
     my $sc=$special_chars[int(rand(length($sccc)))];
     substr($password,int(rand(length($password))), 1, $sc);
   }
   return $password
}

#########################################################################
# Setup signal handling #################################################
#########################################################################
sub setup_signal_handling {
  our $state;

  # We only worry with signal handling for Term::ReadLine::Gnu
  if ($state->{'term'}->{term}->ReadLine ne 'Term::ReadLine::Gnu') {
    return 0;
  }

  # We don't want Term::Readline::Gnu catching signals, except for WINCH.
  # I really don't understand why, but I know via experimentation.
  my $term = $state->{'term'}->{term};
  $term->Attribs->{catch_signals}  = 0;
  $term->Attribs->{catch_sigwinch} = 1; # Window resizes
  $term->clear_signals();

  # Install a signal handler to catch SIGINT (^C). Unsafe signal handling
  # (through POSIX::SigAction) is required to deal with Term::ReadLine::Gnu.
  # We don't even try for other readlines due to their limited functionality.
  sigaction SIGINT, new POSIX::SigAction
    sub {
      our $state;
      # We could be using one of a couple of ReadLine terminals; the one
      # from Term::ShellUI ($state->{'term'}->{term}) or one from one of
      # our cli_NNN commands ($state->{active_readline}). We will assume
      # the Term::ShellUI one here, and override that below if needed.
      my $term = $state->{'term'}->{term};

      # We need to pull the Carp longmess to see if we're sitting in a
      # a cli_XXXX function instead of at a readline prompt.
      my $mess = longmess();
      #print Dumper( $mess );
      if ($mess =~ m/main::(cli_\w+)\(/) {
        #warn "It appears that SIGINT was called from $1\n";
        # Let certain cli_NNN()s know when a SIGINT was last called
        $state->{signals}->{INT} = [gettimeofday];
        # If the cli_NNN has set an active_readline we need to work with it
#        if (defined($state->{active_readline})) {
#          my $term = $state->{active_readline};
#          $term->free_line_state();
#          $term->cleanup_after_signal();
#          $term->reset_after_signal();
#        }
      } else { # If not in a cli_XXX(), assume a Term::ShellUI prompt
        my $bold="\e[1m";
        my $red="\e[31m";
        my $yellow="\e[33m";
        my $clear="\e[0m";
        my $underline=color('underline');
        #$term->echo_signal_char(SIGINT); # Puts ^C on the next line. :(
        print "^C$yellow   - use the \"quit\" command to exit.$clear\n";
        $term->free_line_state();
        $term->cleanup_after_signal();
        $term->reset_after_signal();
        $term->{line_buffer}="";        # Clear the input buffer
        $term->forced_update_display(); # Force update the display
      }
      return 0;
    };

  # There is a bad assumption in these next two blocks of code, and
  # that is that the user will only do a Ctrl-Z or continue while
  # the program is sitting at a Term::ShellUI readline() prompt.
  # That is safe most of the time, but a TODO item is to go back and
  # inject code (or find and use a Term::ShellUI interface) to know
  # if the program was sitting at readline() when these signals fired.
  #
  # Handle signal TSTP - terminal stop (user pressing Ctrl-Z)
  sigaction SIGTSTP, new POSIX::SigAction
	  sub {
		our $state;
		my $term = $state->{'term'}->{term};
		$term->cleanup_after_signal();
		$term->reset_after_signal();
	  };
  # Handle signal CONT - continue signal (assuming after Ctrl-Z).
  sigaction SIGCONT, new POSIX::SigAction
	  sub {
		our $state;
		my $term = $state->{'term'}->{term};
		$term->cleanup_after_signal();
		$term->reset_after_signal();
		$term->forced_update_display(); # Force update the display
	  };
}

########################################################################
# Unix-style, "touch" a file
########################################################################
sub touch_file {
  my $filename = shift @_;
  if (! -f $filename) {
    my $fh=new FileHandle;
    open($fh, "> $filename");
    close($fh);
  }
  my $sig_pipe_store=$SIG{'PIPE'};
  $SIG{'PIPE'} = 'IGNORE';
  my $now=time;
  my $retval=utime $now, $now, $filename;
  $SIG{'PIPE'} = $sig_pipe_store;
return($retval);
}

########################################################################
# POD ##################################################################
########################################################################

=head1 NAME

kpcli - A command line interface to KeePass database files.


=head1 DESCRIPTION

A command line interface (interactive shell) to work with KeePass
database files (http://http://en.wikipedia.org/wiki/KeePass).  This
program was inspired by my use of "kedpm -c" combined with my need
to migrate to KeePass. The curious can read about the Ked Password
Manager at http://kedpm.sourceforge.net/.

=head1 USAGE

Please run the program and type "help" to learn how to use it.

=head1 PREREQUISITES

This script requires these non-core modules:

C<Crypt::Rijndael> - libcrypt-rijndael-perl on Ubuntu 10.04

C<Term::ReadKey>   - libterm-readkey-perl on Ubuntu 10.04

C<Sort::Naturally> - libsort-naturally-perl on Ubuntu 10.04

C<File::KeePass>   - libfile-keepass-perl on Ubuntu 12.04

C<Term::ShellUI>   - libterm-shellui-perl on Ubuntu 12.10

It is also recommended that you install C<Term::ReadLine::Gnu> which will
give you command history and tab completion functionality. That module is
in the libterm-readline-gnu-perl package on Ubuntu.

You can optionally install C<Clipboard> and C<Tiny::Capture> to use the
clipboard features; http://search.cpan.org/~king/Clipboard/ and
libcapture-tiny-perl on Ubuntu 10.04.

You can optionally install C<Data::Password> to use the pwck feature
(Password Quality Check); libdata-password-perl on Ubuntu 10.04.

=head1 CAVEATS AND WORDS OF CAUTION

Only interoperability with KeePassX (http://www.keepassx.org/) has been
tested.  File::KeePass seems to have a bug related to some "unknown" data
that KeePassX stores in the *.kdb file. This program deletes those unknown
data when saving. Research into libkpass http://libkpass.sourceforge.net/)
has revealed what File::KeePass classifies as "unknown" are the times for
created/modified/accessed/expires as well as "flags" (id=9), but only for
groups -- File::KeePass seems to handle those fields just fine for entries.
I have not found any ill-effect from dropping those fields when saving and
so that is what kpcli does today to work around this File::KeePass bug.

=head1 BUGS

=head2 Using Ctrl-D to Exit

Versions of Term::ShellUI prior to v0.9. do not have the ability to trap
Ctrl-D exits by the client program. I submitted a patch to remedy that
and it made it into Term::ShellUI v0.9. Please upgrade if kpcli asks you to.

=head2 Multiple Entries or Groups With the Same Name in the Same Group

This program does not support multiple entries in the same group having
the exact same name, nor does it support multiple groups at the same
level having the same name, and it likely never will. KeepassX does
support those.  This program detects and alert when an opened database
file has those issues, but it does not refuse to save (overwrite) a file
that is opened like that. Saves are actually safe (no data loss) as long
as the user has not touched one of the duplicately-named items.

=head1 AUTHOR

Lester Hightower <hightowe at cpan dot org>

=head1 LICENSE

This program may be distributed under the same terms as Perl itself.

=head1 CREDITS

Special thanks to Paul Seamons, author of C<File::KeePass>, and to
Scott Bronson, author of C<Term::ShellUI>. Without those two modules
this program would not have been practical for me to author.

=head1 CHANGELOG

 2010-Nov-28 - v0.1 - Initial release.
 2010-Nov-28 - v0.2 - Encrypt the master password in RAM.
 2010-Nov-29 - v0.3 - Fixed master password encryption for saveas.
 2010-Nov-29 - v0.4 - Fixed code to work w/out Term::ReadLine::Gnu.
                      Documented File::KeePass v0.1 hierarchy bug.
 2010-Nov-29 - v0.5 - Made find command case insensitive.
                      Bugfix in new command (path regex problem).
 2010-Nov-29 - v0.6 - Added lock file support; warn if a lock exists.
 2010-Dec-01 - v0.7 - Further documented the group fields that are
                       dropped, in the CAVEATS section of the POD.
                      Sort group and entry titles naturally.
 2010-Dec-23 - v0.8 - Worked with File::KeePass author to fix a couple
                       of bugs and then required >=v0.03 of that module.
                      Sorted "/_found" to last in the root group list.
                      Fixed a "database changed" state bug in cli_save().
                      Made the find command ignore entries in /Backup/.
                      Find now offers show when only one entry is found.
                      Provided a patch to Term::ShellUI author to add
                       eof_exit_hook and added support for it to kpcli.
 2011-Feb-19 - v0.9 - Fixed bugs related to spaces in group names as
                       reported in SourceForge bug number 3132258.
                      The edit command now prompts to save on changes.
                      Put scrub_unknown_values_from_all_groups() calls
                       back into place after realizing that v0.03 of
                      File::KeePass did not resolve all of the problems.
 2011-Apr-23 - v1.0 - Changed a perl 5.10+ regex to a backward-compatable
                       one to resolve SourceForge bug number 3192413.
                      Modified the way that the /Backup group is ignored
                       by the find command to stop kpcli from croaking on
                       multiple entries with the same name in that group.
                       - Note: There is a more general bug here that
                               needs addressing (see BUGS section).
                      An empty title on new entry aborts the new entry.
                      Changed kdb files are now detected/warned about.
                      Tested against Term::ShellUI v0.9, which has my EOF
                       hook patch, and updated kpcli comments about it.
                      Term::ShellUI's complete_history() method was
                       removed between v0.86 and v0.9 and so I removed
                       kpli's call to it (Ctrl-r works for history).
                      Added the "icons" command.
 2011-Sep-07 - v1.1 - Empty DBs are now initialized to KeePassX style.
                      Fixed a couple of bugs in the find command.
                      Fixed a password noecho bug in the saveas command.
                      Fixed a kdb_has_changed bug in the saveas command.
                      Fixed a cli_open bug where it wasn't cli_close'ing.
                      Fixed variable init bugs in put_master_passwd().
                      Fixed a false warning in warn_if_file_changed().
 2011-Sep-30 - v1.2 - Added the "export" command.
                      Added the "import" command.
                      Command "rmdir" asks then deletes non-empty groups.
                      Command "new" can auto-generate random passwords.
 2012-Mar-03 - v1.3 - Fixed bug in cl command as reported in SourceForge
                       bug number 3496544.
 2012-Apr-17 - v1.4 - Added key file support based on a user contributed
                       patch with SourceForge ID# 3518388.
                      Added my_help_call() to allow for longer and more
                       descriptive command summaries (for help command).
                      Stopped allowing empty passwords for export.
 2012-Oct-13 - v1.5 - Fixed "help <foo>" commands, that I broke in v1.4.
                      Command "edit" can auto-generate random passwords.
                      Added the "cls" and "clear" commands from a patch
                       with SourceForge ID# 3573930.
                      Tested compatibility with File::KeePass v2.03 and
                       made minor changes that are possible with >=2.01.
                      With File::KeePass v2.03, kpcli should now support
                       KeePass v2 files (*.kdbx).
 2012-Nov-25 - v1.6 - Hide passwords (red on red) in the show command
                       unless the -f option is given.
                      Added the --readonly command line option.
                      Added support for multi-line notes/comments;
                       input ends on a line holding a single ".".
 2013-Apr-25 - v1.7 - Patched to use native File::KeePass support for key
                       files, if the File::KeePass version is new enough.
                      Added the "version" and "ver" commands.
                      Updated documentation as Ubuntu 12.10 now packages
                       all of kpcli's dependencies.
                      Added --histfile command line option.
                      Record modified times on edited records, from a
                       patch with SourceForge ID# 3611713.
                      Added the -a option to the show command.
 2013-Jun-09 - v2.0 - Removed the unused Clone module after a report that
                       Clone is no longer in core Perl as of v5.18.0.
                      Added the stats and pwck commands.
                      Added clipboard commands (xw/xu/xp/xx).
                      Fixed some long-standing tab completion bugs.
                      Warn if multiple groups or entries are titled the
                       same within a group, except for /Backup entries.
 2013-Jun-10 - v2.1 - Fixed several more tab completion bugs, and they
                       were serious enough to warrant a quick release.
 2013-Jun-16 - v2.2 - Trap and handle SIGINT (^C presses).
                      Trap and handle SIGTSTP (^Z presses).
                      Trap and handle SIGCONT (continues after ^Z).
                      Stopped printing found dictionary words in pwck.

=head1 TODO ITEMS

  Cleanup the suboptimal assumptions around SIGTSTP and SIGCONT.
  Some work is completed (cli_pwck and cli_stats) but some other is
  barely even started (cli_new and cli_edit). To do those the "right"
  way, new_edit_single_line_input() needs to be reworked to use
  readline() with a prompt, and new_edit_multiline_input() needs to
  be reviewed and possibly reworked as well.

  Consider http://search.cpan.org/~sherwin/Data-Password-passwdqc/
  for password quality checking.

=head1 OPERATING SYSTEMS AND SCRIPT CATEGORIZATION

=pod OSNAMES

Unix-like (written and tested on Ubuntu Linux 10.04.1 LTS).

=pod SCRIPT CATEGORIES

UNIX/System_administration

=cut

