#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (C) 2017 Matthew Warren
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Better Jamf Policy Deferral
    Allows much more flexibility in user policy deferrals.
"""

import os
import sys
import time
import argparse
import datetime
import plistlib
import subprocess
from AppKit import NSWorkspace
from SystemConfiguration import SCDynamicStoreCopyConsoleUser

# Configuration
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Deferment LaunchDaemon Config
# LaunchDaemon label: reverse-domain-formatted organization identifier.
# Do not include '.plist'!
DEFAULT_LD_LABEL = "com.contoso.deferred-policy"
# Trigger: What custom trigger should be called to actually kick off the policy?
DEFAULT_LD_JAMF_TRIGGER = "trigger_for_deferred_policy"
# Max time: What is the maximum time we will allow for deferral? 
# 604800 is 7 days.
DEFAULT_LD_MAX_TIME = "604800"

# If any app listed here is running on the client, no GUI prompts will be shown
# and this program will exit silently with a non-zero exit code.
# Examples included are to prevent interrupting presentations.
BLOCKING_APPS = ['Keynote', 'Microsoft PowerPoint']

# Paths to binaries
JAMF = "/usr/local/bin/jamf"
JAMFHELPER = ("/Library/Application Support/JAMF/bin/jamfHelper.app/Contents"
              "/MacOS/jamfHelper")
LAUNCHCTL = "/bin/launchctl"

# Prompt GUI Config
GUI_WINDOW_TITLE = "IT Notification"
GUI_HEADING_DEFAULT = "Software Updates are ready to be installed."
GUI_ICON = ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources"
            "/AlertCautionIcon.icns")
GUI_MESSAGE_DEFAULT = """Software updates are available for your Mac.

NOTE: Some required updates will require rebooting your computer once installed.

You may schedule these updates for a convenient time by choosing when to start installation.
"""
# The order here is important as it affects the display of deferment options in
# the GUI prompt. We set 300 (i.e. a five minute delay) as the first and
# therefore default option.
GUI_DEFER_OPTIONS = ["300", "0", "1800", "3600", "14400", "43200",
                     "86400", "259200", "432000", "604800"]
GUI_BUTTON = "Okay"

# Confirmation dialog Config
GUI_S_HEADING = "Update scheduled"
GUI_S_ICON = ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources"
              "/AlertCautionIcon.icns")
GUI_S_BUTTON = "OK"
# This string should contain '{date}' somewhere so that it may be replaced by
# the specific datetime for which installation is scheduled
GUI_S_MESSAGE = """Installation of required updates will begin on {date}."""

# Error message dialog
GUI_E_HEADING = "An error occurred."
GUI_E_ICON = ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources"
              "/AlertStopIcon.icns")
GUI_E_MESSAGE = ("A problem occurred processing your request. Please contact "
                 "your administrator for assistance.")

# Program Logic
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def get_console_user(store=None):
    username, uid, gid = (SCDynamicStoreCopyConsoleUser(None, None, None) or [None])
    username = [username,""][username in [u'loginwindow', None, u'']]
    return (username, uid)


def choices_with_default(choices, default):
    """This closure defines an argparser custom action that ensures an argument
       value is in a list of choices, and if not, sets the argument to a default
       value.
       Implementing this argparser action instead of using only a 'choices' list
       for the argument works better for a script called from Jamf where an
       optional parameter may be omitted from the policy definition, but
       subsequent parameters are passed, ie. script.py 1 2 3 [omitted] 5 6
    """
    class customAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            if (values in choices) or (values == default):
                setattr(args, self.dest, values)
            else:
                setattr(args, self.dest, default)

    return customAction


def build_argparser():
    """Creates the argument parser"""
    description = "Allows much more flexibility in user policy deferrals."
    parser = argparse.ArgumentParser(description=description)

    # Collect parameters 1-3 into a list; we'll ignore them
    parser.add_argument("params", nargs=3)

    # Assign names to other passed parameters
    parser.add_argument("mode", nargs="?",
                        action=choices_with_default(['prompt', 'cleanup'],
                                                    'prompt'))
    parser.add_argument("launchdaemon_label",
                        default=DEFAULT_LD_LABEL, nargs="?")
    parser.add_argument("jamf_trigger",
                        default=DEFAULT_LD_JAMF_TRIGGER, nargs="?")
    parser.add_argument("max_time",
                        default=DEFAULT_LD_MAX_TIME, nargs="?")
    parser.add_argument("gui_heading",
                        default=GUI_HEADING_DEFAULT, nargs="?")
    parser.add_argument("gui_message",
                        default=GUI_MESSAGE_DEFAULT, nargs="?")
    return parser.parse_known_args()[0]


def calculate_deferment(add_seconds):
    """Returns the timedelta day, hour and minute of the chosen deferment
    Args:
        (int) add_seconds: Number of seconds into the future to calculate
    Returns:
        (int) day: Day of the month
        (int) hour: Hour of the day
        (int) minute: Minute of the hour
        (str) fulldate: human-readable date
    """
    add_seconds = int(add_seconds)
    now = datetime.datetime.now()
    diff = datetime.timedelta(seconds=add_seconds)
    future = now + diff
    return (int(future.strftime("%d")),
            int(future.strftime("%-H")),
            int(future.strftime("%-M")),
            str(future.strftime("%B %-d at %-I:%M %p")))


def display_prompt(gui_heading, gui_message, gui_deferral, jamfhelper_uid):
    """Displays prompt to allow user to schedule update installation
    Args:
        (str) gui_heading: Heading for window
        (str) gui_message: Message for window
        (list) gui_deferral: List of deferral times (as strs), 
                             capped at max in main.
        (int) jamfhelper_uid: UID of console_user for launchctl
    Returns:
        (int) defer_seconds: Number of seconds user wishes to defer policy
        OR
        None if an error occurs
    """
    cmd = [LAUNCHCTL, 'asuser', str(jamfhelper_uid), JAMFHELPER,
           '-windowType', 'utility',
           '-title', GUI_WINDOW_TITLE,
           '-heading', gui_heading,
           '-icon', GUI_ICON,
           '-description', gui_message,
           '-button1', GUI_BUTTON,
           '-showDelayOptions',
           ' '.join(gui_deferral),
           '-lockHUD']
    error_values = ['2', '3', '239', '243', '250', '255']
    # Instead of returning an error code to stderr, jamfHelper always returns 0
    # and possibly returns an 'error value' to stdout. This makes it somewhat
    # spotty to check for some deferrment values including 0 for 'Start Now'.
    # The return value is an integer, so leading zeroes are dropped. Selecting
    # 'Start Now' should technically return '01'; instead, only '1' is returned
    # which matches the 'error value' for 'The Jamf Helper was unable to launch'
    # All we can do is make sure the subprocess doesn't raise an error, then
    # assume (yikes!) a return value of '1' equates to 'Start Now'
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, err = proc.communicate()
        # Check that the return value does not represent an 'error value'
        if not out in error_values:
            # Special case for 'Start Now' which returns '1'
            if out == '1':
                return 0
            else:
                return int(out[:-1])
        else:
            return None
    except:
        # Catch possible CalledProcessError and OSError
        print "An error occurred when displaying the user prompt."
        return None


def display_confirm(start_date, jamfhelper_uid):
    """Displays confirmation of when user scheduled update to install
    Args:
        (str) start_date: human-readable datetime of scheduled install
        (int) jamfhelper_uid: UID of console user for launchctl.
    Returns:
        None
    """
    confirm = subprocess.check_output([LAUNCHCTL, 'asuser',
                                       str(jamfhelper_uid), JAMFHELPER,
                                       '-windowType', 'utility',
                                       '-title', GUI_WINDOW_TITLE,
                                       '-heading', GUI_S_HEADING,
                                       '-icon', GUI_S_ICON,
                                       '-description',
                                       GUI_S_MESSAGE.format(date=start_date),
                                       '-button1', GUI_S_BUTTON,
                                       '-timeout', "60",
                                       '-lockHUD'])


def display_error(jamfhelper_uid):
    """Displays a generic error if a problem occurs
    Args:
        (int) jamfhelper_uid: UID of console user for launchctl.
    Returns:
        None
    """
    errmsg = subprocess.check_output([LAUNCHCTL, 'asuser',
                                      str(jamfhelper_uid), JAMFHELPER,
                                      '-windowType', 'utility',
                                      '-title', GUI_WINDOW_TITLE,
                                      '-heading', GUI_E_HEADING,
                                      '-icon', GUI_E_ICON,
                                      '-description', GUI_E_MESSAGE,
                                      '-button1', "Close",
                                      '-timeout', "60",
                                      '-lockHUD'])


def get_running_apps():
    """Return a list of running applications"""
    procs = []
    workspace = NSWorkspace.sharedWorkspace()
    running_apps = workspace.runningApplications()
    for app in running_apps:
        procs.append(app.localizedName())
    return procs


def detect_blocking_apps():
    """Determines if any blocking apps are running
    Args:
        none
    Returns:
        (bool) true/false if any blocking app is running
    """
    blocking_app_running = False
    running_apps = get_running_apps()
    for app in BLOCKING_APPS:
        if app in running_apps:
            print "Blocking app {} is running.".format(app)
            blocking_app_running = True
    return blocking_app_running


def write_launchdaemon(job_definition, path, label, kickstart):
    """Writes the passed job definition to a LaunchDaemon
    Args:
        (dict) job_definition: job as defined in main
        (str) path: path to LaunchDaemon
        (str) label: plist/LaunchDaemon label
        (bool) kickstart: If True, kickstart LaunchDaemon (run immediately)
    Returns:
        None
    """

    success = True

    try:
        with open(path, 'w+') as output_file:
            plistlib.writePlist(job_definition, output_file)
    except IOError:
        print "Unable to write LaunchDaemon!"
        success = False

    # Permissions and ownership
    try:
        os.chmod(path, 0644)
    except:
        print "Unable to set permissions on LaunchDaemon!"
        success = False

    try:
        os.chown(path, 0, 0)
    except:
        print "Unable to set ownership on LaunchDaemon!"
        success = False

    # Load job properly.
    try:
        bootstrap_job = subprocess.Popen([LAUNCHCTL, 'bootstrap',
                                          'system', path],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        bootstrap_job.communicate()
        if bootstrap_job.returncode > 0:
            print "Unable to bootstrap LaunchDaemon!"
            success = False
    except:
        print "Unable to use launchctl!"
        success = False

    domain_target = 'system/' + label
    try:
        enable_job = subprocess.Popen([LAUNCHCTL, 'enable', domain_target],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        enable_job.communicate()
        if enable_job.returncode > 0:
            print "Unable to enable LaunchDaemon!"
            success = False
    except:
        print "Unable to use launchctl!"
        success = False

    if kickstart:
        try:
            kickstart_job = subprocess.Popen([LAUNCHCTL, 'kickstart',
                                              domain_target],
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
            kickstart_job.communicate()
            if kickstart_job.returncode > 0:
                print "Unable to kickstart LaunchDaemon!"
                success = False
        except:
            print "Unable to use launchctl!"
            success = False

    return success


def main():
    """Main program"""
    # Build the argparser
    args = build_argparser()

    # Assemble path to LaunchDaemon
    # Jamf passes ALL script parameters where they are blank or not, so we need
    # to test that the label argument is not blank
    if args.launchdaemon_label == "":
        # Use the default value from the head of the script
        ld_label = DEFAULT_LD_LABEL
    else:
        # Use whatever was passed
        ld_label = args.launchdaemon_label
    ld_path = os.path.join('/Library/LaunchDaemons',
                           '{}.plist'.format(ld_label))

    if args.mode == 'prompt':

        console_user, console_user_uid = get_console_user()
        if not console_user:
            print "No user is logged in, so the prompt cannot appear. Exiting."
            sys.exit(1)

        # Make sure the policy hasn't already been deferred
        if os.path.exists(ld_path):
            print "It appears the user has already chosen to defer this policy."
            sys.exit(1)

        # Check for blocking apps
        if detect_blocking_apps():
            print "One or more blocking apps are running."
            sys.exit(1)

        # Get the maximum time we will allow. 5 minutes is the absolute minimum.
        if args.max_time == "":
            maximum_time = DEFAULT_LD_MAX_TIME
        elif args.max_time < 300:
            maximum_time = 300
        else:
            maximum_time = args.max_time
        # Cycle through the default times. If they are less than or equal to 
        # the maximum time, keep them. Otherwise discard. Bottom floor will
        # always be 5 minutes.
        defer_max = [option for option in GUI_DEFER_OPTIONS
                if int(option) <= int(maximum_time)]

        # Use defaults for the message if no args were passed.
        if args.gui_heading == "":
            gui_head = GUI_HEADING_DEFAULT
        else:
             gui_head = args.gui_heading

        if args.gui_message == "":
            gui_mess = GUI_MESSAGE_DEFAULT
        else:
            gui_mess = args.gui_message

        # Prompt the user to select a deferment
        secs = display_prompt(gui_head, gui_mess, defer_max, console_user_uid)
        if secs is None:
            # Encountered an error, bail
            display_error(console_user_uid)
            sys.exit(1)

        # Again, Jamf may pass a literal "" (blank) value so check for that in
        # the policy trigger
        if args.jamf_trigger == "":
            # Use the script-specified default
            policy_trigger = DEFAULT_LD_JAMF_TRIGGER
        else:
            # Use what was passed
            policy_trigger = args.jamf_trigger

        # Define the LaunchDaemon
        daemon = {'Label': args.launchdaemon_label,
                  'UserName': 'root',
                  'GroupName': 'wheel',
                  'LaunchOnlyOnce': True,
                  'ProgramArguments': ['/usr/local/bin/jamf',
                                       'policy',
                                       '-event',
                                       policy_trigger]
                 }

        # Handle start interval of LaunchDaemon based on user's deferrment
        if secs == 0:
            # User chose to "start now" so we will kickstart the LaunchDaemon.
            ld_kickstart = True

        else:
            # User chose to defer, so calculate the deltas and set the
            # StartCalendarInterval key
            day, hour, minute, datestring = calculate_deferment(secs)
            daemon['StartCalendarInterval'] = {'Day': day,
                                            'Hour': hour,
                                            'Minute': minute
                                            }
            ld_kickstart = False

        # Try to write the LaunchDaemon
        if write_launchdaemon(daemon, ld_path, ld_label, ld_kickstart):
            # Show confirmation of selected date if deferred
            if secs > 0:
                display_confirm(datestring, console_user_uid)

            sys.exit(0)

        else:
            display_error(console_user_uid)
            sys.exit(1)

    elif args.mode == 'cleanup':
        # Check if the LaunchDaemon exists
        if os.path.exists(ld_path):
            # Remove the file
            # Normally you would unload the job first, but since that job will
            # be running the script to remove itself, the policy execution would
            # hang. No bueno. Instead, combining the LaunchOnlyOnce key and
            # unlinking the file ensures it only runs once and is then deleted
            # so it doesn't load back up on next system boot.
            try:
                os.remove(ld_path)
                print "File at {} removed".format(ld_path)
            except OSError:
                print "Unable to remove {}; does it exist?".format(ld_path)

            sys.exit(0)

        else:
            print "No LaunchDaemon found at {}".format(ld_path)
            # Nothing to do, so exit
            sys.exit(0)


if __name__ == '__main__':
    main()