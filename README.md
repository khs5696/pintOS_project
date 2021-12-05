Brand new pintos for Operating Systems and Lab (CS330), KAIST, by Youngjin Kwon.

The manual is available at https://casys-kaist.github.io/pintos-kaist/.

File System
4-0 : file system init과 관련
4-1 : FAT관련 함수
4-2 : free_map을 사용하던 기존의 filesys를 FAT를 사용하도록 수정
4-3 : file extension
4-4 : subdirectory


* dir_open에서 calloc으로 dir를 만드는데, dir_close에서 free를 해주긴 함
    ->메모리 누수 안 일어나려면 close 확실하게 했는지 다시 한 번 더 확인!!!!!!