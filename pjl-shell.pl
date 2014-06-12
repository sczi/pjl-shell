#!/usr/bin/perl
# pjl-shell.pl
# www.attackvector.org
# Author of original parts unknown.

use IO::Socket;
use Getopt::Long;

my $useuel=1,$listdisk=0,$target;
$socket, $directory;

my $result=GetOptions
   (
      'useuel!'   => \$useuel,
      'listdisk!' => \$listdisk,
      'host=s'    => \$target,
   );
   
if ((!defined $target) && (defined $ARGV[0])) { $target=$ARGV[0] };

if(!$target) {
   print "Usage: $0 <ip>\n";
   exit(0);
}

if (defined $target) {
   $socket=opensocket($target);
}

my $finish=0;

my %cmdhash=
   (
      'open'   => \&cmd_open,
      'quit'   => \&cmd_quit,
      'bye'    => \&cmd_quit,
      'drives' => \&cmd_drives,
      'dir'    => \&cmd_dir,
      'ls'     => \&cmd_dir,
      'cd'     => \&cmd_cd,
      'get'    => \&cmd_get,
      'put'    => \&cmd_put,
      'mkdir'  => \&cmd_mkdir,
      'del'    => \&cmd_del,
      'rm'     => \&cmd_del,
      'readymsg'   => \&cmd_rmsg,
      'config' => \&cmd_config,
      'status' => \&cmd_status,
      'raw'    => \&cmd_raw,
      'help'   => \&cmd_help,
   );

while (!$finished) {
   print "Current dir: $directory\n";
   print "pjlftp> ";
   my $command=<STDIN>;
   chomp($command);
   my @cmdlist=split(/ /,$command);
   $cmdlist[0]=lc($cmdlist[0]);

   while(my($cmd,$func) = (each %cmdhash)) {
      if ($cmd eq $cmdlist[0]) {
         shift(@cmdlist);
         $finished=&$func(@cmdlist);
      }
         
   }
}

exit(0);
foreach my $check (@checks) {
   @response=sendprinter($socket, $check->{PJL});
   if ($check->{name} eq "Filesystem") {
      shift(@response);
   }
   foreach my $line (@response) {
      chomp($line);
      $line =~ s/\"//g;
      $line =~ s/^\s+//;
      if ($check->{name} eq "Filesystem") {
         my @files=split(/\s+/,$line);
         print "$check->{name} $files[0]\n";
         print " Total Size: $files[1]\n";
         print " Free Space: $files[2]\n";
         print " Location: $files[3]\n";
         print " Label: $files[4]\n";
         if ($listdisk) {
            print "  FILE\t\t\tTYPE\t\tSIZE\n";
            my @objects=displaydir($socket,1,$files[0] . '\\');
         }
      } else {
         print "$check->{name}: ${line}\n";
      }
   }
}

close($socket);
exit(0);

sub sendprinter {
   my $socket=$_[0];
   my $command='@PJL ' . $_[1];
   my @strings;
   my $result;
   my $escape=pack("ca8",0x1b,'%-12345X');
   my $term = "\r\n";
   my $send = $command . $term;
   
   if ($useuel) {
      $send=$escape . $command . $term . $escape;
   }
   
   $socket->send("@PJL\r\n");
   $socket->send($send);
   
   my $bytes;
   my $firstnl=0;
   if ($command =~ /PJL FSUPLOAD/) {
      $bytes=$command;
      $bytes =~ s/^.*SIZE=//;
   }

   unless ($command =~ /FSMKDIR/ or
           $command =~ /FSDOWNLOAD/ or
           $command =~ /FSDELETE/) {
       while (sysread($socket, $byte, 1) == 1) {
          if ($command =~ /PJL FSUPLOAD/) {
             if ($firstnl == 0 && unpack("c",$byte) == 0x0a) {
                $firstnl=1;
             }
             $bytes-- if ($firstnl==1);
#             print "bytes is: $bytes\n";
             last if ($bytes==0);
          } else {
             last if (unpack("c",$byte) == 0x0c);
          }
          $result .= $byte;
       }
       @strings=split(/\n/, $result);
   }

   return @strings;
}

sub displaydir {
   my $socket=$_[0];
   my $path=$_[1];
   my @objects=cataloguedir($socket,$path);

   if ($#objects < 0) {
      print "<EMPTY>\n";
   }
   foreach $object (@objects) {
      my $sep=(substr($path,length($path)-1) ne '\\')?'\\':'';
      print "$object->{type}\t$object->{size}\t$path$sep$object->{name}\n";
   }
}

sub cataloguedir {
   my $socket=$_[0];
   my $volume=$_[1];
   
   my @response;
   my $base="FSDIRLIST NAME=";
   my @objects;
   my $command=$base . '"' . $volume . '"' . " ENTRY=1 COUNT=128";

   @response=sendprinter($socket, $command);
   shift(@response);

   shift(@response);
   foreach my $line (@response) {
      chomp($line);
      my @params=split(/\s+/,$line);
      my $type=$params[1];
      my $size=$params[2];
      $type =~ s/^TYPE=//;
      $size =~ s/^SIZE=//;
      my $dirent = {
         name => $params[0],
         type => $type,
         size => $size
      };
      push(@objects,$dirent);
   }
   
   return @objects;
}

sub opensocket {
   my $target=$_[0];
   my $socket=new IO::Socket::INET (
      PeerAddr => $target,
      PeerPort => '9100',
      Proto => tcp,
   );

   die "Error: $@\n" unless $socket;
   return $socket;
}

sub cmd_open {
   $target=$_[0];
   if (defined($target)) {
      if (defined($socket)) { close($socket) };
      $socket=opensocket($target);
   } else {
      print("No host provided\n");
   }
   return 0;
}

sub cmd_close {
   if (defined($socket)) { close($socket) };
   return 0;
}

sub cmd_quit {
   return 1;
}

sub cmd_drives {
   my @response=sendprinter($socket,"INFO FILESYS");
   shift(@response);
   
   if ($response[0] =~ '^VOLUME') { 
      shift(@response);
   }
   foreach my $line (@response) {
      chomp($line);
      $line =~ s/\"//g;
      $line =~ s/^\s+//;
      # my @details=split(/\s+/,$line);
      # print("$details[0]\n");
      print "$line\n";
   }   
}

sub cmd_dir {
   if (!defined($directory)) {
      print("No current directory\n");
      return 0;
   }
   
   displaydir($socket,$directory);
   return 0;
}

sub cmd_cd {
   my $dir=$_[0];
   
   $dir=$dir . "\\";

   if ((substr $dir,0,1) eq "!") {
       undef $directory;
       $dir = substr $dir,1;
   }
   
   if (defined $directory) { $dir=$directory . $dir; };
   if (defined $directory && $dir =~ /\.\.\\$/) {
      my $position=rindex($directory,"\\",length($directory)-2);
      if ($position > 0) {
         $directory=substr($directory, 0, $position+1);
      }
      return 0
   }
   
   my @response=sendprinter($socket, 'FSQUERY NAME="' . $dir . '"');
   shift(@response);
   if (scalar(@response) == 0) {
      $directory=$dir;
   } else {
      print("Directory $dir is invalid\n");
   }
   return 0;
}

sub cmd_get {
   my $file=$_[0];
   
   open(OUTFILE,">","$file") or die $!;
   binmode(OUTFILE);
   
   my $size;
   my $file = $directory . $file;
   my @response=sendprinter($socket, 'FSQUERY NAME="' . $file . '"');
   if (scalar(@response) != 1) {
      print("File $file doesn't exist\n");
      return 0;
   } else {
       ($size) = $response[0] =~ /SIZE=(\d+)/;
#      $size=$response[0];
#      $size =~ s/^.*SIZE=//;
   }
   
   $size += 1;
#   print "size is : $size\n";
   my @response=sendprinter($socket, 'FSUPLOAD NAME="' . $file . '" OFFSET=0 SIZE=' . $size);
   shift(@response);
   foreach my $item (@response) {
      print OUTFILE "$item\n";
   }
   close(OUTFILE);
   return 0;
}

sub cmd_put {
   my $file=$_[0];
   
   open(INFILE,"<","$file") or die $!;
   binmode(INFILE);
   
   my $size = -s "$file";
   my $ofile = $directory . $file;
   my $buffer;
   
   my $count=read(INFILE,$buffer,$size);
   my @response=sendprinter($socket, 'FSDOWNLOAD FORMAT:BINARY SIZE=' . $size . ' NAME="' . $ofile . '"' . "\r\n" . $buffer);
   close(OUTFILE);
   return 0;
}   

sub cmd_mkdir {
   my $dir=$_[0];
   my $dir=$directory . $dir;
   my @response=sendprinter($socket, 'FSMKDIR NAME="' . $dir . '"');
   return 0;
}

sub cmd_del {
   my $dir=$_[0];
   my $dir=$directory . $dir;
   my @response=sendprinter($socket, 'FSDELETE NAME="' . $dir . '"');
   return 0;
}

sub cmd_rmsg {
   my $rmsg=$_[0];
   print "Setting message to: $rmsg - This takes a minute, be patient\n";
   my @response = sendprinter($socket, 'RDYMSG DISPLAY="' . $rmsg . '"');
   return 0;
}

sub cmd_status {
   my @response = sendprinter($socket, "INFO STATUS");
   shift(@response);
   foreach $line (@response) {
      print "$line\n";
   }
   return 0;
}

sub cmd_config {
   my @response = sendprinter($socket, "INFO CONFIG");
   shift(@response);
   foreach $line (@response) {
      print "$line\n";
   }
   return 0;
}

sub cmd_raw {
   my @response = sendprinter($socket, "@_");
   shift(@response);
   foreach $line (@response) {
      print "$line\n";
   }
   return 0;
}

sub cmd_help {
   print "Available commands:\n";
   print "\topen\t - Open a new connection\n";
   print "\tquit\t - Terminate session\n";
   print "\tbye\t - Terminate session\n";
   print "\tdrives\t - List available volumes\n";
   print "\tdir\t - List files and directories\n";
   print "\tls\t - List files and directories\n";
   print "\tcd\t - Change directory\n";
   print "\tget\t - Download a file\n";
   print "\tput\t - Upload a file\n";
   print "\tmkdir\t - Make a new directory\n";
   print "\tdel\t - Delete a file\n";
   print "\trm\t - Delete a file\n";
   print "\treadymsg\t - Change the ready message\n";
   print "\tconfig\t - Show the hardware config\n";
   print "\tstatus\t - Show the current printer status\n";
   print "\traw\t - Manually type commands - ie: raw INFO STATUS\n";
   print "\thelp\t - Durr..\n";
   return 0;
}
