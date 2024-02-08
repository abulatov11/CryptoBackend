import subprocess

class RunProcess:
    
    def __init__(self, command=None, timeout=None):
        self.command = None
        self.timeout = None
        self.stdout = None
        self.stderr = None
        if command:
            self.set_command(command)
        if timeout:
            self.set_timeout(timeout)

    def set_command(self, command):
        self.command = command
        return self 

    def set_timeout(self, timeout):
        timeout = float(timeout) if timeout is not None else None
        if timeout < 0:
            raise ChildProcessError("Timeout can't be less than 0")
        self.timeout = timeout

    def get_output(self):
        return self.stdout

    def get_error(self):
        return self.stderr

    def run(self):
        self.stdout = None
        self.stderr = None
        if not len(self.command):
            raise ChildProcessError("Process is expecting commands to run")
        
        processes= []

        try:
            if not isinstance(self.command[0], list):
                self.command = [self.command]
            
            for command in self.command:
                if not processes:
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=processes[-1].stdout)
                processes.append(process)
            
            self.stdout, self.stderr = processes[-1].communicate(timeout=self.timeout)
            self.stdout = str(self.stdout.decode("utf-8")).strip()
            self.stderr = str(self.stderr.decode("utf-8")).strip()
        except subprocess.TimeoutExpired:
            self.stderr = "Timeout reached. Process killed."
        except Exception as e:
            raise e
        #print("OUTPUT: '%s'" % str(self.stdout))
        #print("")
        #print("ERROR: '%s'" % str(self.stderr))
        #print("")
        return self.stdout, self.stderr
