#!/usr/bin/perl

use strict;
use vars qw/ $CFG $IN $DB /;
use CGI;
use DBI;
use JSON;
use Digest::SHA1 qw/sha1_hex/;
use Data::Dumper;

$CFG = {
    db_dsn          => 'dbi:mysql:database=redmine;host=localhost',
    db_username     => 'root',
    db_password     => '',

    debug           => 1,

    session_path    => '/tmp',
    session_fprefix => 'redminejson_',
    session_length  => 60*60, # 1 hour
};

main();

sub main {
# --------------------------------------------------
    sanity_test() or die "Whoa, seems like something's not right.";
    init();
    my $args = $IN->Vars;

# Figure out what we want to be doing
    my $do_fname = 'do_' . ( $args->{do} || "unknown" );
    no strict 'refs';
    if ( $do_fname !~ /^\w+$/ or not ${"main::"}{$do_fname} ) {
        $do_fname = 'do_unknown';
    };
    my $result = (\&{"main::$do_fname"})->($args);
    use strict 'refs';

# Results back to the user
    print $IN->header('text/plain');
    print to_json($result);
}

sub init {
# --------------------------------------------------
# Initializes the CGI and database handler
#
    $IN = CGI->new;
    $DB = DBI->connect( $CFG->{db_dsn}, $CFG->{db_username}, $CFG->{db_password} );
    return 1;
}

sub R_ERROR {
# --------------------------------------------------
# Creates an error response and allows the attaching
# of an error message
# 
    my ( $message ) = @_;
    return {
        success => 0,
        error   => $message,
    }
}

sub R_SUCCESS {
# --------------------------------------------------
# Returns a success response and allows the attaching
# of a data payload
#
    my ( $data ) = @_;
    return {
        success => 1,
        data    => $data,
    }
}

sub do_unknown {
# --------------------------------------------------
# Returns when we don't know what the user is trying
# to do
#
    R_ERROR( 'Uknown function requested' );
}

sub do_login {
# --------------------------------------------------
# Attempt to auth the user's credentials against the
# database. We will issue a session token in response
# along with sending the user the set of primary data
# that will be used by the tps system (eg. 
# information related to the user's projects, current
# scheduled timelines, etc)
#
    my ( $args ) = @_;

# Authenticate the user
    my $username   = $args->{login} or return R_ERROR('Require Login');
    my $clear_pass = $args->{pass} or return R_ERROR('Require Password');
    my $enc_pass   = sha1_hex($clear_pass);
    my $user = $DB->selectrow_hashref("select * from users where login = ?",{},$username);
    $user or return R_ERROR('Invalid Login');
    $user->{hashed_password} eq $enc_pass or return R_ERROR('Invalid Login');

# User is authenticated. Create the session
    my $session = session_create({user=>$user});

# Now let's fetch some useful information for the user, such as...

# 1. what projects they are associted with
    my $projects = db_projects($user);

# 2. fetch a list of active issues for the user
    my $issues = db_issues($user);

# 3. what's the user's schedule for today
    my $tics = $CFG->{debug}?(time-60*60*24*7):time;
    my $schedule = db_schedule( $user, $tics ); 

# 4. and find out how much time the user has already put forward
    my $time_log = db_time_log( $user, $tics );

    my $result = {
        session_id => $session->{session_id},
        issues     => $issues,
        projects   => $projects,
        schedule   => $schedule,
        time_log   => $time_log,
    };

    R_SUCCESS($result);
}

sub do_logout {
# --------------------------------------------------
# Remove a user's session by deauth'ing a user's
# session token
#
    my ( $args ) = @_;
    my $session_id = $args->{session_id} or return R_ERROR('No session ID found');
    session_revoke($session_id);
    R_SUCCESS("You are now logged out");
}

sub do_logreport {
# --------------------------------------------------
# Fetch a basic report of the user's activities
#
    my ( $args ) = @_;
    my $session_id = $args->{session_id}    or return R_ERROR('No session ID found');
    my $session = session_load($session_id) or return R_ERROR('No session found');
    my $date_tics = $CFG->{debug}?(time-60*60*24*7):time;
    my @d = localtime($date_tics);
    $d[4]++;
    $d[5]+=1900;
    my $date = sprintf "%04i-%02i-%02i", @d[5,4,3];

# Find out how much time the user has already put forward
    my $time_log = $DB->selectall_arrayref("
                            select id, project_id, issue_id, hours, comments
                            from time_entries
                            where
                                user_id  = $session->{data}{user}{id}
                                and spent_on = '$date'
                            ") or die $DB->errstr;

    R_SUCCESS($time_log);
}

sub do_logadd {
# --------------------------------------------------
# Append a log-time to the database for the user
#
    my ( $args ) = @_;
    my $session_id = $args->{session_id}    or return R_ERROR('No session ID found');
    my $session = session_load($session_id) or return R_ERROR('No session found');
    my $project_id = $args->{project_id}    or return R_ERROR('No project ID found');
    my $hours      = $args->{hours}         or return R_ERROR('No hours found');

# Parse out the date
    my $date_tics = $CFG->{debug}?(time-60*60*24*7):($args->{date}||time);
    my @d = localtime($date_tics);
    $d[4]++;
    $d[5]+=1900;
    my $date = sprintf "%04i-%02i-%02i", @d[5,4,3];
    my $datetime = sprintf "%04i-%02i-%02i %02i:%02i:%02i", @d[5,4,3,2,1,0];

# Figure out what week of the year it is. Ugly calculation, wow
    my $tweek = int(
                    ($d[7]                       # julian day
                        + (7000+$d[6]-$d[7]) % 7 # handle the day of the week offset
                        )/7
                )+1;                             # index off 0, so we need to correct

# Assemble the new record
    my $new_rec = {
        project_id  => $project_id,
        user_id     => $session->{data}{user}{id},
        issue_id    => $args->{issue_id},
        hours       => $hours,
        comments    => $args->{comments}||'',
        activity_id => '',
        spent_on    => $date,
        tyear       => $d[5],
        tmonth      => $d[4],
        tweek       => $tweek,
        created_on  => $datetime,
        updated_on  => $datetime,
    };
    my @values;
    my $fields = join ",", map {push @values, $new_rec->{$_}; $_} keys %$new_rec;
    my $placeholders = join ",", map {"?"} keys %$new_rec;
    my $insert_sth = $DB->prepare("insert into time_entries ($fields) values ($placeholders)") or return R_ERROR($DB->errstr);
    my $r = $insert_sth->execute(@values) or return R_ERROR($DB->errstr);

# Now return 'er
    my $result = {
        log_new => $new_rec,
        result  => $r,
    };
    return R_SUCCESS($result);
}

sub do_logremove {
# --------------------------------------------------
# Remove a log entry from the data for the user
#
    my ( $args )   = @_;
    my $session_id = $args->{session_id}    or return R_ERROR('No session ID found');
    my $session    = session_load($session_id) or return R_ERROR('No session found');
    my $log_id     = $args->{log_id} or return R_ERROR('No Log ID provided');
    my $log_entry  = $DB->selectrow_hashref("select * from time_entries where id = ?",{},$log_id) or return R_ERROR("No log entry by that ID");
    $log_entry->{user_id} == $session->{data}{user}{id} or return R_ERROR("Not your entry!");
    my $del_sth    = $DB->prepare("delete from time_entries where id=?") or return R_ERROR("Delete query prepare failed");
    my $result     = $del_sth->execute($log_id) or return R_ERROR("Could not delete the record. Execute returned error");
    return R_SUCCESS($log_entry);
}

sub do_stats {
# --------------------------------------------------
# Returns the stats associated with a user
#
    my ( $args ) = @_;
    my $session_id = $args->{session_id}    or return R_ERROR('No session ID found');
    my $session   = session_load($session_id) or return R_ERROR('No session found');

# Now let's fetch some useful information for the user, such as...
    my $user = $session->{data}{user} or return R_ERROR('No user found');

# 1. what projects they are associted with
    my $projects = db_projects($user);

# 2. fetch a list of active issues for the user
    my $issues = db_issues($user);

# 3. what's the user's schedule for today
    my $tics = $CFG->{debug}?(time-60*60*24*7):time;
    my $schedule = db_schedule( $user, $tics ); 

# 4. and find out how much time the user has already put forward
    my $time_log = db_time_log( $user, $tics );

# 5. the activities that are available to the user
    my $activities = db_activities();

    my $result = {
        issues     => $issues,
        projects   => $projects,
        schedule   => $schedule,
        time_log   => $time_log,
        activities => $activities,
    };

    R_SUCCESS($result);
}

sub db_projects {
# --------------------------------------------------
# Return all projects a user has been associated with
#
    my ( $user ) = @_;
    my $projects = $DB->selectall_arrayref("
                            select projects.id,projects.name 
                            from members,projects 
                            where 
                                user_id = $user->{id}
                                and project_id = projects.id 
                                and status = 1 
                            order by name
                            ") or die $DB->errstr;
    $projects = {map {@$_} @$projects};
    return $projects;
}

sub db_issues {
# --------------------------------------------------
# Returns a list of all the active issues that
# are associated with the user
#
    my ( $user ) = @_;
    my $issues = $DB->selectall_arrayref("
                            select 
                                i.id, subject, i.project_id, due_date, e.name
                            from issues as i, issue_statuses as s, enumerations as e
                            where
                                assigned_to_id = $user->{id}
                                and status_id = s.id
                                and is_closed = 0
                                and i.priority_id = e.id
                                and e.type = 'IssuePriority'
                            order by
                                e.position desc, due_date
                            ") or die $DB->errstr;
    return $issues;
}

sub db_schedule {
# --------------------------------------------------
    my ( $user, $date ) = @_;

    if ( $date !~ /^\d+-\d+-\d+$/ ) {
        my @d = localtime($date);
        $d[4]++;
        $d[5]+=1900;
        $date = sprintf "%04i-%02i-%02i", @d[5,4,3];
    }

    my $schedule = $DB->selectall_arrayref("
                            select
                                project_id, hours
                            from schedule_entries 
                            where 
                                user_id = $user->{id}
                                and date = '$date'
                            ") or die $DB->errstr;

    return $schedule;
}

sub db_time_log {
# --------------------------------------------------
    my ( $user, $date ) = @_;

    if ( $date !~ /^\d+-\d+-\d+$/ ) {
        my @d = localtime($date);
        $d[4]++;
        $d[5]+=1900;
        $date = sprintf "%04i-%02i-%02i", @d[5,4,3];
    }

    my $time_log = $DB->selectall_arrayref("
                            select t.id, t.project_id, issue_id, i.subject, hours, comments
                            from time_entries as t left join issues as i
                                 on ( issue_id = i.id )
                            where
                                user_id  = $user->{id}
                                and spent_on = '$date'
                            order by
                                t.created_on
                            ") or die $DB->errstr;

    return $time_log;
}

sub db_activities {
# --------------------------------------------------
# Return a list of all the activities that a log
# entry can hold
#
    my $activities = $DB->selectall_arrayref("
                            select id, name 
                            from enumerations
                            where type = 'TimeEntryActivity'
                            order by position
                        ") or die $DB->error;
    return $activities;
}

sub session_create {
# --------------------------------------------------
# Create a new, blank session for the user
#
    my ( $data ) = @_;
    my ( $session_id, $fpath );
    do {
        $session_id = sha1_hex(time*$$*rand(100_000));
        $fpath = $CFG->{session_path} . "/" 
                . $CFG->{session_fprefix} 
                . $session_id;
    } while ( -f $fpath );
    my $session = {
        session_id => $session_id,
        data       => $data
    };
    my $fpath_buf = to_json( $session );
    open my $fh, ">$fpath";
    print $fh $fpath_buf;
    close $fh;

    return $session;
}

sub session_load {
# --------------------------------------------------
# Load a session and touch it
#
    my ( $session_id ) = @_;
    return unless $session_id;
    return unless $session_id =~ /^\w+$/;
    my $fpath = $CFG->{session_path} . "/" 
                . $CFG->{session_fprefix} 
                . $session_id;
    return unless -f $fpath;
    open my $fh, "<$fpath";
    local $/;
    my $fpath_buf = <$fh>;
    close $fh;
    my $session = from_json($fpath_buf);
}

sub session_revoke {
# --------------------------------------------------
# Destroy the session data associated with a token
# key
#
    my ( $session_id ) = @_;
    return unless $session_id =~ /^\w+$/;
    my $fpath = $CFG->{session_path} . "/" 
                . $CFG->{session_fprefix} 
                . $session_id;
    unlink $fpath;
}

sub session_cleanup {
# --------------------------------------------------
# Go through and reap all the timed out sessions
#
}

sub sanity_test {
# --------------------------------------------------
# Basic check of the system to see that nothing bad
# had happened to the database and whatever else.
# We don't want redmine to go through a version
# bump without there being someone to have a look
# at what's changed. We don't want this code to start
# breaking data!
#
    return 1;
}


