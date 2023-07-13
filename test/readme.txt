使用virtualbox：
将 test、test_close_server_for_server.c 和 close_client_for_server 拷贝到现有 test 目录下
修改 test 目录下的 Makefile 文件，增加对 test_close_server_for_server.c 的编译
在 /vagrant/tju_tcp/test 路径下，用“test close”测试四次挥手

使用docker：
将 test-docker版、test_close_server_for_server.c 和 close_client_for_server 拷贝到现有 test 目录下
将 test-docker版 重命名为 test
修改 test 目录下的 Makefile 文件，增加对 test_close_server_for_server.c 的编译
在 /vagrant/tju_tcp/test 路径下，用“test close”测试四次挥手