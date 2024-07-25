# INSTALL DEPS
sudo yum install -y gcc readline-devel libicu-devel zlib-devel openssl-devel

# DOWNLOAD VERSION 16.1 POSTGRESQL
wget https://ftp.postgresql.org/pub/source/v16.1/postgresql-16.1.tar.gz

# UNPACK 
tar -xvzf postgresql-16.1.tar.gz

# ACCESS DIR
cd postgresql-16.1

# CONFIGURE FOR COMPILE
./configure --bindir=/usr/bin --with-openssl

# COMPILE AND INSTALL
sudo make -C src/bin install
sudo make -C src/include install
sudo make -C src/interfaces install
