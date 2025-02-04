FROM ubuntu:20.04

RUN rm /etc/dpkg/dpkg.cfg.d/excludes

ENV DEBIAN_FRONTEND noninteractive
ENV LC_CTYPE=C.UTF-8
COPY sources.list /etc/apt/
RUN dpkg --add-architecture i386
RUN apt-get update && \
    dpkg -l | grep ^ii | cut -d' ' -f3 | grep -v '^libgcc-s1:amd64$' | xargs apt-get install -y --reinstall && \
    apt-get install -y sudo \
                       build-essential \
                       git \
                       gcc-multilib \
                       g++-multilib \
                       clang \
                       llvm \
                       gdb \
                       gdb-multiarch \
                       qemu-system-x86 \
                       kmod \
                       openssh-server \
                       python-is-python3 \
                       python3-dev \
                       python3-pip \
                       ipython3 \
                       default-jdk \
                       net-tools \
                       iproute2 \
                       nasm \
                       cmake \
                       rubygems \
                       emacs \
                       vim \
                       nano \
                       ed \
                       silversearcher-ag \
                       zsh \
                       tmux \
                       screen \
                       binwalk \
                       strace \
                       ltrace \
                       autoconf \
                       socat \
                       netcat \
                       nmap \
                       curl \
                       wget \
                       tcpdump \
                       exiftool \
                       hexedit \
                       parallel \
                       patchelf \
                       genisoimage \
                       whiptail \
                       binutils \
                       bsdmainutils \
                       bsdutils \
                       debianutils \
                       diffutils \
                       elfutils \
                       findutils \
                       gnupg-utils \
                       keyutils \
                       pcaputils \
                       pcre2-utils \
                       psutils \
                       squashfs-tools \
                       unzip \
                       virtualenvwrapper \
                       upx-ucl \
                       man-db \
                       manpages-dev \
                       bison \
                       bc \
                       flex \
                       cpio \
                       libelf-dev \
                       libtool-bin \
                       libini-config-dev \
                       libssl-dev \
                       libffi-dev \
                       libgmp-dev \
                       libglib2.0-dev \
                       libseccomp-dev \
                       libedit-dev \
                       libpixman-1-dev \
                       libc6:i386 \
                       libc6-dev-i386 \
                       libstdc++6:i386 \
                       libncurses5:i386 \
                       expect

RUN yes | unminimize

RUN useradd -s /bin/bash -m hacker && \
    passwd -d hacker

RUN mkdir /opt/linux && wget -O - https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.4.tar.gz | tar xzC /opt/linux
WORKDIR /opt/linux/linux-5.4
RUN make defconfig
RUN for CONFIG in \
    CONFIG_9P_FS=y \
    CONFIG_9P_FS_POSIX_ACL=y \
    CONFIG_9P_FS_SECURITY=y \
    CONFIG_BALLOON_COMPACTION=y \
    CONFIG_CRYPTO_DEV_VIRTIO=y \
    CONFIG_DEBUG_FS=y \
    CONFIG_DEBUG_INFO=y \
    CONFIG_DEBUG_INFO_BTF=y \
    CONFIG_DEBUG_INFO_DWARF4=y \
    CONFIG_DEBUG_INFO_REDUCED=n \
    CONFIG_DEBUG_INFO_SPLIT=n \
    CONFIG_DEVPTS_FS=y \
    CONFIG_DRM_VIRTIO_GPU=y \
    CONFIG_FRAME_POINTER=y \
    CONFIG_GDB_SCRIPTS=y \
    CONFIG_HW_RANDOM_VIRTIO=y \
    CONFIG_HYPERVISOR_GUEST=y \
    CONFIG_NET_9P=y \
    CONFIG_NET_9P_DEBUG=n \
    CONFIG_NET_9P_VIRTIO=y \
    CONFIG_PARAVIRT=y \
    CONFIG_PCI=y \
    CONFIG_PCI_HOST_GENERIC=y \
    CONFIG_VIRTIO_BALLOON=y \
    CONFIG_VIRTIO_BLK=y \
    CONFIG_VIRTIO_BLK_SCSI=y \
    CONFIG_VIRTIO_CONSOLE=y \
    CONFIG_VIRTIO_INPUT=y \
    CONFIG_VIRTIO_NET=y \
    CONFIG_VIRTIO_PCI=y \
    CONFIG_VIRTIO_PCI_LEGACY=y \
    ; do echo $CONFIG >> .config; done
RUN make -j$(nproc) bzImage
RUN ln -s $PWD/arch/x86/boot/bzImage ../bzImage && \
    ln -s $PWD/vmlinux ../vmlinux
WORKDIR /

RUN echo '    StrictHostKeyChecking no' >> /etc/ssh/ssh_config && \
    echo '    UserKnownHostsFile=/dev/null' >> /etc/ssh/ssh_config && \
    echo '    LogLevel ERROR' >> /etc/ssh/ssh_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config && \
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/g' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config

RUN mkdir /opt/gdb && wget -O - https://ftp.gnu.org/gnu/gdb/gdb-11.1.tar.gz | tar xzC /opt/gdb && \
    cd /opt/gdb/gdb-11.1 && \
    mkdir build && \
    cd build && \
    ../configure --prefix=/usr --with-python=/usr/bin/python3 && \
    make -j$(nproc) && \
    make install

RUN curl -fsSL https://code-server.dev/install.sh | /bin/sh /dev/stdin
RUN mkdir -p /opt/code-server/extensions && code-server --extensions-dir=/opt/code-server/extensions --install-extension ms-python.python
#RUN code-server --extensions-dir=/opt/code-server/extensions --install-extension mathematic.vscode-pdf
#RUN code-server --extensions-dir=/opt/code-server/extensions --install-extension analytic-signal.preview-pdf
RUN mv /usr/lib/code-server/lib/vscode/node_modules/@vscode/ripgrep/bin/rg /usr/lib/code-server/lib/vscode/node_modules/@vscode/ripgrep/bin/rg.orig && \
    echo '#!/usr/bin/python \n\
          \n\
          import sys \n\
          import os \n\
          \n\
          sys.argv[0] += ".orig" \n\
          if "--follow" in sys.argv: sys.argv.remove("--follow") \n\
          os.execv(sys.argv[0], sys.argv)' \
    | awk '{$1=$1};1' > /usr/lib/code-server/lib/vscode/node_modules/@vscode/ripgrep/bin/rg && \
    chmod +x /usr/lib/code-server/lib/vscode/node_modules/@vscode/ripgrep/bin/rg

RUN git clone https://github.com/aquynh/capstone /opt/capstone && cd /opt/capstone && ./make.sh && ./make.sh install
#RUN git clone https://github.com/radareorg/radare2 /opt/radare2 && cd /opt/radare2 && sys/install.sh
RUN git clone https://github.com/aflplusplus/aflplusplus /opt/aflplusplus && cd /opt/aflplusplus && make distrib && make install
RUN git clone https://github.com/yrp604/rappel /opt/rappel && cd /opt/rappel && make && cp bin/rappel /usr/bin/rappel
RUN wget https://github.com/0vercl0k/rp/releases/download/v2.0.2/rp-lin-x64 -O /usr/bin/rp++ && chmod +x /usr/bin/rp++

RUN pip install --force-reinstall git+https://github.com/Gallopsled/pwntools#egg=pwntools jupyter flask angr r2pipe asteval psutil

RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg
RUN git clone https://github.com/hugsy/gef /opt/gef
RUN git clone https://github.com/longld/peda /opt/peda
RUN git clone https://github.com/jerdna-regeiz/splitmind /opt/splitmind

RUN ln -s /usr/bin/ipython3 /usr/bin/ipython

# GUI apps (should probably use no-recommends or whatnot)
RUN apt-get update && \
    apt-get install -y tigervnc-standalone-server \
                       novnc \
                       websockify \
                       xfce4 \
                       xfce4-terminal \
                       mousepad \
                       xclip \
                       wireshark && \
    apt-get -y remove --purge at-spi2-core tumbler gvfs-* && \
    apt-get -y autoremove
#RUN wget -q -O - https://github.com$(curl https://github.com/angr/angr-management/releases | grep angr-management-ubuntu.tar.gz | head -n1 | cut -d'"' -f2) | tar xvz -C /opt
RUN wget -q -O /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.5_build/ghidra_10.1.5_PUBLIC_20220726.zip && cd /opt && unzip /tmp/ghidra.zip && mv /opt/ghidra_10.1.5_PUBLIC /opt/ghidra
#COPY desktop/angr-management.desktop /usr/share/applications/
COPY desktop/Ghidra.desktop /usr/share/applications/
COPY desktop/pwncollege_background.jpg /usr/share/backgrounds/
COPY desktop/xfce4 /usr/share/desktop-base/profiles/xdg-config/xfce4
RUN rm /etc/xdg/autostart/* # don't autostart stuff in the desktop

# IDA Freeware: only permissible for free and open deploymets of the pwn.college dojo!
COPY desktop/ida.opt /opt/ida/ida.opt
RUN wget https://out7.hex-rays.com/files/idafree80_linux.run -O /tmp/idafree80_linux.run && chmod 755 /tmp/idafree80_linux.run && /tmp/idafree80_linux.run --optionfile /opt/ida/ida.opt
COPY desktop/ida64.desktop /usr/share/applications/

RUN mkdir /opt/pwn.college
COPY docker-initialize.sh /opt/pwn.college/docker-initialize.sh
COPY docker-entrypoint.sh /opt/pwn.college/docker-entrypoint.sh
COPY setuid_python.c /opt/pwn.college/setuid_python.c
COPY vm /opt/pwn.college/vm
COPY .tmux.conf /opt/pwn.college/.tmux.conf
COPY .gdbinit /opt/pwn.college/.gdbinit
COPY .radare2rc /opt/pwn.college/.radare2rc


RUN gcc /opt/pwn.college/setuid_python.c -o /opt/pwn.college/python && \
    rm /opt/pwn.college/setuid_python.c

RUN ln -s /opt/pwn.college/vm/vm /usr/local/bin/vm

RUN ln -sf /home/hacker/.tmux.conf /root/.tmux.conf && \
    ln -sf /home/hacker/.gdbinit /root/.gdbinit
#    ln -sf /home/hacker/.radare2rc /root/.radare2rc

RUN echo 'pwn.college{uninitialized}' > /flag && \
    chmod 400 /flag

RUN mkdir /challenge

RUN find / -type f -perm -4000 | xargs -r chmod u-s

RUN chmod u+s /opt/pwn.college/python /opt/pwn.college/vm/vm

USER hacker
WORKDIR /home/hacker
ADD --chown=hacker:hacker --chmod=444 esame-si/* /opt/pwn.college/
