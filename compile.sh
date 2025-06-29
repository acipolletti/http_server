 gcc -Os -I. -DSQLITE_THREADSAFE=0 -DSQLITE_ENABLE_FTS4 \
   -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1 \
   -DSQLITE_ENABLE_RTREE -DSQLITE_ENABLE_EXPLAIN_COMMENTS \
   -DHAVE_READLINE \
   -c /home/ac/app/sqlite-amalgamation-3500100/sqlite3.c -ldl -lm -lreadline -lncurses -o /home/ac/app/sqlite-amalgamation-3500100/sqlite3.o

g++ -std=c++17 -pthread -Wall -Wextra -pedantic -O2 -I./src -I./src/include -I/home/ac/app/sqlite-amalgamation-3500100 \
    ./src/server.cpp ./src/auth_routes.cpp ./src/file_routes.cpp ./src/user_file_manager.cpp ./src/auth.cpp ./src/check_mime_type.cpp ./src/send_gmail.cpp ./src/handle_static_contents.cpp /home/ac/app/sqlite-amalgamation-3500100/sqlite3.o -o ./build/http_server \
    -lssl -lcrypto -pthread -lcurl \
    -ldl -lm -lreadline -lncurses

g++ -std=c++17 -pthread -Wall -Wextra -pedantic -O2 -I./src -I./src/include -I/home/ac/app/sqlite-amalgamation-3500100 \
    ./src/fs_server.cpp ./src/check_mime_type.cpp -o ./build/fs_server