#!/usr/bin/perl

###########################################################################
#
# kpcli - KeePass Command Line Interface
#
# Author: Lester Hightower / November 2010
#
# This program was inspired by "kedpm -c" and resulted despite illness
# (or more likely because of it) over the USA Thanksgiving holiday in
# late November of 2010. As a long-time user of the Ked Password Manager
# I really missed a command line interface after getting an Android cell
# phone and switching to KeePass, so that I could access my password
# database on my phone. This program scratches that itch.
#
###########################################################################

use strict;
use FileHandle;
use Getopt::Long;
use File::Basename;
use Data::Dumper qw(Dumper);
use Crypt::Rijndael; # non-core, libcrypt-rijndael-perl on Ubuntu
use Sort::Naturally; # non-core, libsort-naturally-perl on Ubuntu
use Term::ReadKey;   # non-core, libterm-readkey-perl on Ubuntu
use Term::ShellUI;   # non-core, needs Term::ReadLine::Gnu for command history
use File::KeePass;   # non-core
$|=1;

my $DEBUG=0;

my $APP_NAME = basename($0);
$APP_NAME =~ s/\.pl$//;

my $VERSION = "0.7";

my $opts=MyGetOpts();  # Will only return with options we think we can use

# Setup our Term::ShellUI object
my $term = new Term::ShellUI(
    app => $APP_NAME,
    history_file => "~/.$APP_NAME-history",
    keep_quotes => 0,
    commands => {
         "" => { args => sub { shift->complete_history(@_) } },
         "history" => { desc => "Prints the command history",
            doc => "\nSpecify a number to list the last N lines of history" .
            "Pass -c to clear the command history, " .
            "-d NUM to delete a single item\n",
            args => "[-c] [-d] [number]",
            method => sub { shift->history_call(@_) },
         },
         "help" => {
             desc => "Print helpful information",
             args => sub { shift->help_args(undef, @_); },
             method => sub { shift->help_call(undef, @_); }
         },
         "h" => { alias => "help", exclude_from_completion=>1},
         "?" => { alias => "help", exclude_from_completion=>1},
         "cl" => {
             desc => "Change directory and list entries (cd+ls)",
             doc => "\n" .
		"Change the pwd to an absolute or relative path\n" .
		"and list the entries there. This is a useful way\n" .
		"to quickly navigate to a path and have the entries\n" .
		"listed in preparation to run the show command.\n",
             maxargs => 1,
             args => \&complete_groups,
             method => sub { if(cli_cd(@_) == 0) { cli_ls(@_) } },
         },
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
             desc => "Save to a specific filename (saveas <file.kdb>)",
             minargs => 1, maxargs => 1,
             args => \&Term::ShellUI::complete_files,
             proc => \&cli_saveas,
         },
         "open" => {
             desc => "Open a KeePass database file (open <file.kdb>)",
             minargs => 1, maxargs => 1,
             args => \&Term::ShellUI::complete_files,
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
         "show" => {
             desc => "Show an entry: show <path to entry|entry number>",
             doc => "\n" .
		"The show command tries to intelligently determine\n" .
		"what you want to see and to make it easy to display.\n" .
		"Show can take a path to an entry as its argument or\n" .
		"an entry number as shown by the ls command.\n" .
		"\n" .
		"When using entry numbers, they will refer to the last\n" .
		"path when an ls was performed or pwd if ls has not\n" .
		"yet been run.\n" .
		"",
             minargs => 1, maxargs => 1,
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
		"in their title and places matches into \"/_found/\".\n",
             minargs => 1, maxargs => 1, args => "<search string>",
             method => \&cli_find,
         },
         "pwd" => {
             desc => "Print the current working directory",
             maxargs => 0, proc => \&cli_pwd,
         },
         "quit" => {
             desc => "Quit this program (EOF and exit also work)",
             maxargs => 0, method => \&cli_quit,
         },
         "exit" => { alias => "quit", exclude_from_completion=>1},
       },
    );
$term->prompt(\&term_set_prompt);

# Seed our state global variable
our $state={
	'appname' => $APP_NAME,
	'term' => $term,
	'kdb_has_changed' => 0,
	'last_ls_path' => '',
	'put_master_passwd' => \&put_master_passwd,
	'get_master_passwd' => \&get_master_passwd,
	};
# If given --kdb=, open that file
if (length($opts->{kdb})) {
  my $err = open_kdb($opts->{kdb}); # Sets $state->{'kdb'}
  if (length($err)) {
    print "Error opening file: $err\n";
  }
} else {
  $state->{'kdb'} = File::KeePass->new;
}

# Enter the interative kpcli shell session
print "\n" .
	"KeePass CLI ($APP_NAME) v$VERSION is ready for operation.\n" .
	"Type 'help' for a description of available commands.\n" .
	"Type 'help <command>' for details on individual commands.\n";
if ($DEBUG) {print 'Using '.$term->{term}->ReadLine." for readline.\n"; }
if (! $DEBUG && $term->{term}->ReadLine ne 'Term::ReadLine::Gnu') {
  warn "Please install Term::ReadLine::Gnu for better functionality!\n";
}
print "\n";
$term->run();

exit;

############################################################################
############################################################################
############################################################################

sub open_kdb($) {
  my $file=shift @_;
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
  if (! eval { $state->{kdb}->load_db($file, $master_pass) }) {
    die "Couldn't load the file $file: $@";
  }

  if ($state->{placed_lock_file}) {
    touch_file($state->{placed_lock_file});
  }

  $state->{kdb_file} = $file;
  $state->{put_master_passwd}($master_pass);
  $master_pass="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  # Build the %all_grp_paths_fwd and %all_grp_paths_rev structures
  refresh_state_all_paths();

  # Initialize our state into "/"
  cli_cd($term, {'rawline' => "cd /"});

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

  foreach my $me (@{$g}) {
    my @path_to_me = @{$root_path};
    push @path_to_me, $me->{title};
    my $path=join("\0",@path_to_me);
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

  foreach my $me (@{$g}) {
    my @path_to_me = @{$root_path};
    push @path_to_me, $me->{title};
    if (defined($me->{entries})) {
      foreach my $ent (@{$me->{entries}}) {
        my $path=join( "\0", (@path_to_me, $ent->{title}) );
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
  my $found_group=$k->find_group({level=>0,title=>'_found'});
  if (defined($found_group)) {
    my @oldents = $k->find_entries({group=>$found_group->{id}});
    foreach my $ent (@oldents) {
      $k->delete_entry({id => $ent->{id}});
    }
    $k->delete_group({level=>0,title=>'_found'});

    # Because we destroyed /_found we must refresh our $state paths
    refresh_state_all_paths();
  }
}

# Refreshes $state->{all_grp_paths_fwd} and $state->{all_grp_paths_rev}
sub refresh_state_all_paths() {
  our $state;

  my %all_grp_paths_fwd;
  build_all_group_paths(\%all_grp_paths_fwd,$state->{kdb}->groups);
  my %all_grp_paths_rev = reverse %all_grp_paths_fwd;
  $state->{all_grp_paths_fwd}=\%all_grp_paths_fwd;
  $state->{all_grp_paths_rev}=\%all_grp_paths_rev;

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

# A function to properly sort groups by title
sub group_sort($$) {
  my $a=shift @_;
  my $b=shift @_;

  # Backup at level=0 is a special case (KeePassX's Backup group)
  if ($a->{title} eq 'Backup' && $a->{level} == 0) {
    return 1;
  } elsif ($b->{title} eq 'Backup' && $b->{level} == 0) {
    return -1;
  } else {
    return ncmp($a->{title},$b->{title}); # Natural sort
  }
}

# -------------------------------------------------------------------------
# All of the cli_*() functions are below here
# -------------------------------------------------------------------------

sub cli_pwd {
  print get_pwd() . "\n";
}

sub cli_cd {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  my ($cd_cmd,$raw_pathstr)=split(/\s+/,$params->{'rawline'},2);
  # "cd ."
  if ($raw_pathstr =~ m/^[.]$/) {
    return; # nothing to do
  }
  # "cd -"
  if ($raw_pathstr =~ m/^[-]$/) {
    return cli_cd($self, {'rawline' => "cd $state->{oldpwd}"});
  }
  # Everything else is handled by helpers
  return cli_cd_helper($state,normalize_path_string($raw_pathstr));
}

# Takes a possible wacky path whit ".."'s and such and normalizes it into a
# NULL-separated path that we can use as an index into $state->{all_grp_paths_fwd}
sub normalize_path_string($) {
  my $path_string = shift @_;
  our $state;

  # Split the path into @path
  # http://efreedom.com/Question/1-3588341/Implement-Escape-Sequence-Using-Split-Perl
  my $delim="/";
  my $escape="\\";
  my @path = $path_string =~
		/(?:\Q$delim\E|^)((?:\Q$escape\E.|(?!\Q$delim\E).)*+)/gs;
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

  my @e = $k->find_entries({'title =~' => "$search_str"});

  if ( scalar(@e) < 1) {
    print "No matches.\n";
    return;
  }

  # If we get this far we have results to add to a new /_found
  my $found_group = $k->add_group({title => '_found'}); # root level group
  my $found_gid = $found_group->{'id'};
  $k->unlock;
  foreach my $ent (@e) {
    my %new_ent = %{$ent}; # Clone the entity
    $new_ent{id} = int(rand(1000000000000000));
    $new_ent{group} = $found_gid;
    $k->add_entry(\%new_ent);
  }
  $k->lock;

  print " - " . scalar(@e) . " matches found and placed into /_found.\n";

  # Because we added a new /_found we must refresh our $state paths
  refresh_state_all_paths();

}

# Something is going wrong between KeePassX and File::KeePass related to
# the unknown values read/written by File::KeePass from/to files written
# by KeePassX. Commenting out like 378 of File/KeePass.pm is one fix,
# this prevents me from needing to do that by just removing the unknown
# values before saving. If there is a downside to this on the KeePassX
# side I've not found it yet. I do have an email out to Paul, the author
# of File::KeePass, requesting some assistance in grokking the problem.
sub scrub_unknown_values_from_all_groups {
  our $state;
  my $k=$state->{kdb};
  my @all_groups_flattened = $k->find_groups({});
  foreach my $g (@all_groups_flattened) {
    if (defined($g->{unknown})) {
      #warn "Deleting unknown items from $g->{title}\n";
      delete $g->{unknown};
    }
  }
}

sub cli_save($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;
  if (! length($state->{kdb_file})) {
    print "Please use the saveas command for new files.\n";
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
    my $key='';
    ReadMode('raw'); # Turn off controls keys
    while (not defined ($key = ReadKey(-1))) {
      # No key yet
    }
    ReadMode('restore');
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
  scrub_unknown_values_from_all_groups();
  my $k=$state->{kdb};
  $k->unlock;
  my $master_pass=$state->{get_master_passwd}();
  $k->save_db($state->{kdb_file},$master_pass);
  $master_pass="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  print "Saved to $state->{kdb_file}\n";
  $k->lock;
}

sub cli_rm($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

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

  my $target = $params->{args}->[0];
  my $ent=find_target_entity_by_number_or_path($target);
  if (! defined($ent)) {
    return -1;
  }

  $state->{kdb}->unlock;
  print "\n" .
	show_format("Title",$ent->{title}) . "\n" .
	show_format("Uname",$ent->{username}) . "\n" .
	show_format("Pass",$ent->{password}) . "\n" .
	show_format("URL",$ent->{url}) . "\n" .
	show_format("Notes",$ent->{comment}) . "\n" .
	($DEBUG ? show_format("ID",$ent->{id}) . "\n" : '') .
	"\n";
  print &Dumper($ent) . "\n" if ($DEBUG > 2);
  $state->{kdb}->lock;
}

sub cli_edit($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  my $target = $params->{args}->[0];
  my $ent=find_target_entity_by_number_or_path($target);
  if (! defined($ent)) {
    print "Don't see an entry at path: $target\n";
    return -1;
  }

  # Loop through the fields taking edits the user wants to make
  my @fields = get_entry_fields();
  foreach my $input (@fields) {
    if ($input->{hide_entry}) {
      print $input->{txt} . ": ";
    } else {
      print $input->{txt} . " (\"".$ent->{$input->{key}}."\"): ";
    }
    if ($input->{hide_entry}) {
      ReadMode(2); # Hide typing
    }
    my $val = ReadLine(0);
    if ($input->{hide_entry}) { print "\n"; }
    chomp $val;
    if (length($val) && $input->{double_entry_verify}) {
      print "Retype to verify: ";
      my $checkval = ReadLine(0);
      if ($input->{hide_entry}) { print "\n"; }
      chomp $checkval;
      if ($checkval ne $val) {
        print "Entries mismatched. Please try again.\n";
        redo;
      }
    }
    # If the field was not empty, change it to the new $val
    if (length($val)) {
      $state->{kdb}->unlock;
      $ent->{$input->{key}} = $val;
      $state->{kdb}->lock;
    }
    ReadMode(0); # Return to normal
  }

return 0;
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

sub get_entry_fields {
  my @fields = (
	{ key=>'title', txt=>'Title' },
	{ key=>'username', txt=>'Username' },
	{ key=>'password', txt=>'Password',
		hide_entry => 1, double_entry_verify => 1 },
	{ key=>'url', txt=>'URL' },
	{ key=>'comment', txt=>'Notes/Comments' },
	);
  return @fields;
}

sub cli_new($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  my $pwd=get_pwd();
  if ($pwd =~ m/^\/+$/) {
    print "Entries cannot be made in this path ($pwd).\n";
    return -1;
  }

  print "Adding new entry to \"$pwd\"\n";

  # Grab the entries as this $id (pwd) so we can check for conflicts
  my $k=$state->{kdb};
  my $id=$state->{path}->{id};
  my ($this_grp,@trash) = $k->find_groups({id=>$id});
  my @entries = $k->find_entries({group_id => $id});

  my $new_entry = {
    'group' => $id,
  };

  my @fields = get_entry_fields();
  foreach my $input (@fields) {
    print $input->{txt} . ": ";
    if ($input->{hide_entry}) {
      ReadMode(2); # Hide typing
    }
    my $val = ReadLine(0);
    if ($input->{hide_entry}) { print "\n"; }
    chomp $val;
    if ($input->{double_entry_verify}) {
      print "Retype to verify: ";
      my $checkval = ReadLine(0);
      if ($input->{hide_entry}) { print "\n"; }
      chomp $checkval;
      if ($checkval ne $val) {
        print "Entries mismatched. Please try again.\n";
        redo;
      }
    }
    $new_entry->{$input->{key}} = $val;
    ReadMode(0); # Return to normal
  }

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

}

sub cli_saveas($) {
  my $file=shift @_;
  our $state;

  my $master_pass=GetMasterPasswd();
  print "Retype to verify: ";
  my $checkval = ReadLine(0);
  chomp $checkval;
  print "\n";
  if ($master_pass ne $checkval) {
    print "Passwords did not match...\n";
    return;
  }

  scrub_unknown_values_from_all_groups();

  $state->{kdb}->unlock;
  $state->{kdb}->save_db($file,$master_pass);
  $state->{kdb}->lock;

  $state->{kdb}= File::KeePass->new;
  if (! eval { $state->{kdb}->load_db($file, $master_pass) }) {
    die "Couldn't load the file $file: $@";
  }

  $state->{kdb_file} = $file;
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

  my ($mkdir_cmd,$raw_pathstr)=split(/\s+/,$params->{'rawline'},2);
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
  if (defined($group->{entries})) { $entry_cnt=scalar(@{$group->{entries}}); }
  my $group_cnt=0;
  if (defined($group->{groups})) { $group_cnt=scalar(@{$group->{groups}}); }
  if ( ($entry_cnt + $group_cnt) == 0) {
    my $deleted_group = $state->{kdb}->delete_group({ id => $group_id });
  } else {
    print "First remove its $entry_cnt entries and $group_cnt sub-groups.\n";
  }

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

  my ($mkdir_cmd,$raw_pathstr)=split(/\s+/,$params->{'rawline'},2);
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
    }); # root level group
  } elsif (defined($state->{all_grp_paths_fwd}->{$path})) {
    my $group_id=$state->{all_grp_paths_fwd}->{$path};
    $group = $state->{kdb}->add_group({
		title => $newdir,
		group => $group_id,
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
  if ( -f $path ) {
    my $err = open_kdb($path);
    if (length($err)) {
      print "Error opening file: $err\n";
    }
  } else {
    print "Cannot open: $path\n";
  }
}

sub cli_close {
  our $state;

  if ($state->{kdb_has_changed}) {
    print "WARNING: The database has changed and was not saved.\n" .
	"Really close it? [y/N] ";
    my $key='';
    ReadMode('raw'); # Turn off controls keys
    while (not defined ($key = ReadKey(-1))) {
      # No key yet
    }
    ReadMode('restore');
    print "\n";
    if (lc($key) ne 'y') {
      return;
    }
  }

  $state->{kdb_has_changed}=0;
  $state->{'kdb'} = File::KeePass->new;
  if (-f $state->{placed_lock_file}) { unlink($state->{placed_lock_file}); }
  delete($state->{placed_lock_file});
  delete($state->{kdb_file});
  delete($state->{master_pass});
  cli_cd($term, {'rawline' => "cd /"});
}

sub cli_ls($) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  my ($ls_cmd,$path)=split(/\s+/,$params->{'rawline'},2);

  # If we were given a path, use cli_cd() to go there temporarily...
  my $old_path='';
  if (length($path)) {
    $old_path=get_pwd();
    if (cli_cd($term, {'rawline' => "cd $path"})) {
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
    cli_cd($term, {'rawline' => "cd $old_path"});
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

sub cli_quit($$) {
  my $self = shift @_;
  my $params = shift @_;
  our $state;

  if ($state->{kdb_has_changed}) {
    print "WARNING: The database has changed and was not saved.\n" .
	"Really quit? [y/N] ";
    my $key='';
    ReadMode('raw'); # Turn off controls keys
    while (not defined ($key = ReadKey(-1))) {
      # No key yet
    }
    ReadMode('restore');
    if (lc($key) ne 'y') {
      print "\n";
      return;
    }
  }

  if (-f $state->{placed_lock_file}) { unlink($state->{placed_lock_file}); }
  delete($state->{placed_lock_file});
  $self->exit_requested(1);
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
  my $key='';
  ReadMode('raw'); # Turn off controls keys
  while (not defined ($key = ReadKey(-1))) {
    # No key yet
  }
  ReadMode('restore');
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
  my $result = &GetOptions(\%opts, "kdb=s", "help", "h");

  # If the user asked for help or GetOptions complained, give help and exit
  if ($opts{help} || $opts{h} || (! int($result))) {
    print GetUsageMessage();
    exit;
  }

  my @errs=();
  if ((length($opts{kdb}) && (! -e $opts{kdb}))) {
    push @errs, "for option --kdb=<file.kbd>, the file must exist.";
  }

  if (scalar(@errs)) {
    warn "There were errors:\n" .
	"  " . join("\n  ", @errs) . "\n\n";
    die &GetUsageMessage();
  }

  return \%opts;
}

sub GetUsageMessage {
  my $t="Usage: $APP_NAME [--kdb=<file.kdb>]\n" .
  "\n" .
  "    --help\tThis message.\n" .
  "    --kdb\tOptional KeePass 1.x database file to open (must exist)\n" .
  "\n" .
  "Run kpcli with no options and type 'help' at its command prompt to learn\n" .
  "about kpcli's commands.\n";
  "\n";
  return $t;
}

########################################################################
# Command Completion Routines ##########################################
########################################################################

sub complete_groups {
  my $self = shift;
  my $cmpl = shift;
  our $state;

  $self->suppress_completion_append_character();

  my $path = $cmpl->{str} || ".";
  # Tack on trailing slashes for user convenience...
  if ($path =~ m/(^|\/)[.][.]$/) { $path .= "/"; }	# onto "..../.."
  if ($path eq '.') { $path .= "/"; }			# onto a single "."

  my $srch_path=normalize_path_string($path);
  my @possibles = grep(/^$srch_path\0?[^\0]+$/,
				sort keys %{$state->{all_grp_paths_fwd}});
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

return \@results;
}

sub complete_groups_and_entries {
  my $self = shift;
  my $cmpl = shift;
  our $state;

  # Grab the groups for this path
  my $groups=complete_groups($self,$cmpl);

  # Now gather up the entries (code very similar to complete_groups()
  my $path = $cmpl->{str} || ".";
  my $srch_path=normalize_path_string($path);
  my @entries = grep(/^$srch_path\0?[^\0]*$/,
				sort keys %{$state->{all_ent_paths_fwd}});
  # This loop is modifying @entries values in place!
  foreach my $opt (@entries) {
    $opt=humanize_path($opt);
    if ($path =~ m/^(\/+)/) {
      $opt=$1.$opt;
    } else {
      my $pwd=get_pwd(); $pwd=~s/^\///;
      $opt=~s/^$pwd\/+//;
      if ($path =~ m/^[\/.]+/) {
        $opt=$1.$opt;
      }
    }
    # Lop the leading "./" off the head if it was not user supplied
    if ($path !~ m/^[.]\// && $opt =~ m/^[.]\//) { $opt =~ s/^[.]\///; }
    # If the user did supply a leading "./" and we missed it, add it
    if ($path =~ m/^[.]\// && $opt !~ m/^[.]\//) { $opt = "./$opt"; }
  }

  # Merge the groups and entries
  my @possibles = sort (@{$groups}, @entries);
  return \@possibles;
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
sub put_master_passwd($) {
  my $master_pass = shift @_;
  our $state;
  $state->{'master_pass_key'} .= chr(int(255 * rand())) for 1..16;
  $state->{'master_pass_enc_iv'} .= chr(int(255 * rand())) for 1..16;
  $master_pass='CLEAR:' . $master_pass;
  $state->{'master_pass'}=encrypt_rijndael_cbc($master_pass,
		$state->{'master_pass_key'}, $state->{'master_pass_enc_iv'});
  return 0;
}
sub get_master_passwd($) {
  our $state;
  my $master_pass=decrypt_rijndael_cbc($state->{master_pass},
		$state->{'master_pass_key'}, $state->{'master_pass_enc_iv'});
  if ($master_pass=~s/^CLEAR://) {
    return $master_pass;
  } else {
    die "Failed to properly decrypt my copy of the master password.\n";
  }
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

kpcli - A command line interface to KeePass 1.x database files.


=head1 DESCRIPTION

A command line interface (interactive shell) to work with KeePass 1.x
database files (http://http://en.wikipedia.org/wiki/KeePass).  This
program was inspired by my use of "kedpm -c" combined with my need
to migrate to KeePass. The curious can read about the Ked Password
Manager at http://http://kedpm.sourceforge.net/.

=head1 PREREQUISITES

This script requires these non-core modules:

C<Crypt::Rijndael> - "apt-get install libcrypt-rijndael-perl" on Ubuntu

C<Term::ReadKey>   - "apt-get install libterm-readkey-perl" on Ubuntu

C<Sort::Naturally> - "apt-get install libsort-naturally-perl" on Ubuntu

C<Term::ShellUI>   - not packaged on Ubuntu

C<File::KeePass>   - not packaged on Ubuntu

Both of the "not packaged" modules above build very cleanly with the
dh-make-perl tool on Debian and Ubuntu.

It is also recommended that you install C<Term::ReadLine::Gnu> which will
give you command history and completion functionality. That module is in
the libterm-readline-gnu-perl package on Ubuntu.

=head1 CAVEATS AND WORDS OF CAUTION

Only interoperability with KeePassX (http://www.keepassx.org/) has been
tested.  File::KeePass seems to have a bug related to some "unknown" data
that KeePassX stores in the *.kdb file. This program deletes those unknown
data when saving. Research into libkpass http://libkpass.sourceforge.net/)
has shown me that what File::KeePass classifies as "unknown" are the times
for created/modified/accessed/expires as well as "flags" (id=9), but only
for groups -- File::KeePass seems to handle those fields fine for entries.
I have not found any ill-effect from dropping those fields when saving and
so that is what kpcli does today to work around this File::KeePass bug.

=head1 BUGS

=head2 KeePass Database Group/Tree Hierarchy

There is a bug in File::KeePass v0.1 that messes up the hierarchy if
the tree moves "back" more than one level at a time. I tried to fix
the bug but haven't had enough time to figure it out. For now, the bug
is easy to work around. Envision these two hierarchies:

            BREAKS                         WORKS
     ----------------------         -----------------------
          - personal                     - personal
            - web                          - web
              - shopping                     - shopping
              - travel                       - travel
          - work                           - zzz_kpcli_bug
                                         - work

I've reported the File::KeePass bug through rt.cpan.org and will also
try again to fix it myself when I have some time.

=head2 Tab Completion

Tab completion is not perfect. It has problems with some entries that
contain spaces, slashes, and/or backslashes. I don' know if I am doing
something wrong or if Term::ShellUI may have some bugs in its command
completion code.

=head2 Using Ctrl-D to Exit

Pressing Ctrl-D exits the program _without warning_ to the user if the
database has been changed and not saved. Term::ShellUI seems to be at
fault here as there is no way to "hook" into its "exit on Ctrl-D" behavior.

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

=head1 OPERATING SYSTEMS AND SCRIPT CATEGORIZATION

=pod OSNAMES

Unix-like (written and tested on Ubuntu Linux 10.04.1 LTS).

=pod SCRIPT CATEGORIES

UNIX/System_administration

=cut

