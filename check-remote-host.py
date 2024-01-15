"""
Script to check the remote host accessible by SSH.

The main functions support by this script are:
1. Whether the remote host is accessible via ssh.
2. Whether a port is open on the remote host.
3. List the processes running on the remote host.
4. issue a command on remote host and check the output.
5. Check a remote file content.

The ssh credential is defined in config.ini file.
the host info is saved in playbook.yml file.

packages required:
- pydantic
- paramiko
- pyyaml

## Sample `config.ini` file
[default]
some_username = some_password

## Sample `playbook.yml` file
inventory:
  - name: $(group_name)
    username: $(user_name)
    hosts:
      - name: $(host_alias)
        hostname: $(hostname)
        remote:
          - username: $(ps username)
            resource: ps
            output:
              - $(some ps output line)
          - file_path: '/etc/issue'
            resource: file
            content: 'abcd'
          - command: 'pwd'
            resource: cmd
            output: /home/abcd
      - name: $(name_02)
        hostname: $(hostname2)
        skip: true
        remote:
          - username: $(some username)
            resource: ps
            output:
              - $(some output)

"""
import configparser
import logging
import socket
import sys
import tempfile
from pathlib import Path
from typing import Optional, List, Tuple, Set, Union, Literal, Annotated

import paramiko
import yaml
from pydantic import BaseModel, Field, SecretStr

logging.basicConfig(
    format="%(asctime)s.%(msecs)03d %(levelname)6s %(lineno)4d %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.ERROR,
    stream=sys.stdout,
)

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class RemoteHost(BaseModel):
    hostname: str
    username: str
    password: Optional[SecretStr] = Field(default='')
    port: Optional[int] = Field(default=22)


class RemoteCommand(BaseModel):
    resource: Literal['cmd']
    command: str
    output: str = Field(default='')
    actual: str = Field(default='')
    skip: bool = Field(default=False)

    def check(self) -> bool:
        log.info(f'Checking output of command {self.command!r} ...')
        if self.actual != self.output:
            log.error(f'Command output does not match\n'
                      f'expect ===\n%r\nactual ===\n%r\n',
                      self.output, self.actual)
        else:
            log.info('Done')


class RemoteFile(BaseModel):
    resource: Literal['file']
    file_path: str
    content: str = Field(default='')
    actual: str = Field(default='')
    skip: bool = Field(default=False)

    def check(self):
        log.info(f'Checking remote file {self.file_path!r} ...')
        if self.actual != self.content:
            log.error(f'File content does not match\n'
                      f'expect ===\n%r\nactual ===\n%r\n',
                      self.content, self.actual)
        else:
            log.info('Done')


class RemoteUserPS(BaseModel):
    resource: Literal['ps']
    username: Optional[str] = Field(default=None)
    output: List[str] = Field(default_factory=list)
    actual: List[str] = Field(default_factory=list)
    skip: bool = Field(default=False)

    def check(self):
        log.info(f'Checking processes of user {self.username!r} ...')
        for missing in (set(self.output) - set(self.actual)):
            log.error('Missing process: %r', missing)
        log.info(f'Done')


RemoteResource = Annotated[Union[RemoteUserPS, RemoteFile, RemoteCommand], Field(discriminator='resource')]


class HostInfo(BaseModel):
    name: str
    hostname: str
    port: Optional[int] = 22
    remote: List[RemoteResource] = Field(default_factory=list)
    skip: bool = Field(default=False)


class GroupInfo(BaseModel):
    name: str
    username: str
    hosts: List[HostInfo] = Field(default_factory=list)


class Inventory(BaseModel):
    inventory: List[GroupInfo] = Field(default_factory=list)


def get_password(config, remote_host: str, username: str) -> str:
    section_name = remote_host if remote_host in config else 'default'
    password = config[section_name].get(username)
    return password


def check_host_port(host: str, port: Optional[int] = 22, *,
                    timeout: Optional[int] = 5) -> bool:
    """Check whether the port is open on a remote host."""
    log.info(f'Checking port {port} on remote host {host} ...')
    port_is_open = False
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        port_is_open = True
    except (socket.timeout, socket.error) as e:
        log.error(str(e))
    log.info(f'Port {port} is open on remote host {host}? {port_is_open}.')
    return port_is_open


class Client:
    def __init__(self):
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def check_resource(self, remote_host: RemoteHost, remote_resource: RemoteResource):
        if remote_resource.skip:
            log.info('Skipping %r', remote_resource)
            return
        if isinstance(remote_resource, RemoteUserPS):
            remote_resource.username = remote_resource.username or remote_host.username
            output = self.get_user_ps(remote_host, user=remote_resource.username)
        elif isinstance(remote_resource, RemoteFile):
            output = self.get_remote_file_content(remote_host, remote_path=remote_resource.file_path)
        elif isinstance(remote_resource, RemoteCommand):
            output = self.get_remote_command_output(remote_host, command=remote_resource.command)
        else:
            raise RuntimeError(f'unknown resource type {remote_resource!r}')
        remote_resource.actual = output
        remote_resource.check()

    def check_ssh(self, remote_host: RemoteHost) -> bool:
        """Check whether remote host is accessible via SSH."""

        ssh_port_is_open = check_host_port(remote_host.hostname, remote_host.port)
        ssh_ok = False
        if ssh_port_is_open:
            try:
                self._ssh_login(remote_host)
                ssh_ok = True
            except Exception as e:
                log.error(str(e))
                ssh_ok = False
            finally:
                self._ssh_client.close()

        return ssh_ok

    def get_user_ps(self, remote_host: RemoteHost, *, user: Optional[str] = None):
        user = user or remote_host.username
        cmd = f'ps ugx -u {user}'
        output, error_message = self._remote_exec(remote_host, cmd)
        if error_message:
            log.error(error_message)
        return self._parse_ps_output(output)

    def get_hostname(self, remote_host: RemoteHost) -> str:
        cmd = 'hostname'
        output, error_message = self._remote_exec(remote_host, cmd)
        if error_message:
            log.error(error_message)
        return output.strip().lower()

    def check_hostname(self, remote_host: RemoteHost) -> bool:
        actual_hostname = self.get_hostname(remote_host)
        if actual_hostname != remote_host.hostname:
            log.error('Actual hostname %r does not match expected hostname %r',
                      actual_hostname, remote_host.hostname
                      )
        return remote_host.hostname == self.get_hostname(remote_host)

    def get_remote_file_content(self, remote_host: RemoteHost, remote_path: str) -> str:
        """
        Get the remote file content as a string.
        :param remote_host: RemoteHost
        :param remote_path:
        :return: string representation of the remote file.
        """
        cmd = f'cat {remote_path}'
        log.info(f'Getting content of file {remote_path!r} on {remote_host.hostname} ...')
        output, error_message = self._remote_exec(remote_host, cmd)
        if error_message:
            log.error(error_message)
        return output

    def get_remote_command_output(self, remote_host: RemoteHost, command: str) -> str:
        log.info(f'Executing command: {command!r} on remote host: {remote_host!r}')
        output, error_message = self._remote_exec(remote_host, command)
        if error_message:
            log.error(error_message)
        log.info('Output is: %r',output)
        return output

    def download_remote_file(self, remote_host: RemoteHost, remote_path: str, *,
                             local_path: Optional[str] = None) -> None:
        """Download a file from remote host and save it to local path."""
        self._ssh_login(remote_host)
        sftp_client = self._ssh_client.open_sftp()
        with tempfile.TemporaryDirectory():
            local_file = Path(remote_path).name
            sftp_client.get(remote_path, local_file)
            if local_path:
                Path(local_file).rename(Path(local_path))
            else:
                Path(local_file).rename(Path.cwd().joinpath(local_file))

        self._ssh_client.close()

    def _parse_ps_output(self, ps_output: str) -> Set[str]:
        return set([
            " ".join(line.split()[10:]) for line in ps_output.splitlines()
        ]) - {'COMMAND'}

    def _remote_exec(self, remote_host: RemoteHost, command: str) -> Tuple[str, str]:
        log.debug('Executing command: %r on remote host: %s as user: %s',
                  command, remote_host.hostname, remote_host.username)
        self._ssh_login(remote_host)
        std_in, std_out, std_err = self._ssh_client.exec_command(command)
        output = std_out.read().decode().strip()
        error_message = std_err.read().decode().strip()
        self._ssh_client.close()
        return output, error_message

    def _ssh_login(self, remote_host: RemoteHost):
        log.debug("Logging into remote host: %s as user: %s",
                  remote_host.hostname, remote_host.username)
        self._ssh_client.connect(
            hostname=remote_host.hostname,
            username=remote_host.username,
            password=remote_host.password.get_secret_value(),
            port=remote_host.port
        )


def main():
    config = configparser.ConfigParser()
    config.read('config.ini')
    playbook = yaml.safe_load(Path('playbook.yml').read_text())
    inv = Inventory(**playbook)
    client = Client()
    for group in inv.inventory:
        log.info('## Checking group: %r', group.name)
        for host in group.hosts:
            if host.skip:
                log.info('### Skipping host %r', host.hostname)
                continue
            else:
                log.info('### Checking host %r', host.hostname)
            password = get_password(config, remote_host=host.hostname, username=group.username)
            remote_host = RemoteHost(hostname=host.hostname, username=group.username, password=password, port=host.port)
            if not client.check_ssh(remote_host):
                log.error('Failed to ssh to %r', remote_host)
                continue
            if not client.check_hostname(remote_host):
                log.error('Failed to validate hostname %r', remote_host)
                continue

            for res in host.remote:
                client.check_resource(remote_host, res)


if __name__ == '__main__':
    main()
