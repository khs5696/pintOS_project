#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/fat.h"
#include "devices/disk.h"
#include "threads/thread.h"
#include "threads/malloc.h"


/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");
	// inode_init : 그냥 list init해주는 게 전부
	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
   // 최초 thread의 시작 directory는 Root Directory
	thread_current()->work_dir = dir_open_root();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
   /* Original FS */
#ifdef EFILESYS
   fat_close ();
#else
   free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
// 4-2-0 create syscall에서 사용되던 filesys_create 수정
/* 4-4-2 파일 혹은 디렉토리 생성시 사용
         현재 dir는 무조건 root directory -> root direct
         ory만 생성하겠다는 뜻 -> 이걸 바꿔야함! */
#ifdef EFILESYS
bool
filesys_create (const char * name, off_t initial_size) {
   disk_sector_t inode_sector = 0;
   // parsing process : 경로 & 파일
   char * create_file = (char *) malloc(NAME_MAX+1);
   struct dir * target_dir = search_target_dir(name, create_file);
   
   // directory path가 유효한 경로인지 확인
   if (target_dir == NULL)
      goto clean;

   // 새로운 file을 생성하기 위해 inode_disk가 만들어질 새로운 공간이 필요하므로,
   // fat_create_chain(0) 호출 -> cluster를 리턴하기 때문에 sector로 변환
   // inode_create에서 inode를 disk에 저장하고 initial_size가 포함되는 sector를 할당해 0으로 초기화
   bool success = ((inode_sector = cluster_to_sector(fat_create_chain(0)))
         && inode_create (inode_sector, initial_size, true)
         && dir_add (target_dir, create_file, inode_sector));
   if (!success && inode_sector != 0)
      fat_remove_chain(sector_to_cluster(inode_sector), 0);

clean:
   free(create_file);
   // target_dir == NULL이어도 지장 없음
   dir_close(target_dir);
   return success;
}
#else
bool
filesys_create (const char *name, off_t initial_size) {
   disk_sector_t inode_sector = 0;

   struct dir *dir = dir_open_root ();
   bool success = (dir != NULL
         && free_map_allocate (1, &inode_sector)
         && inode_create (inode_sector, initial_size, true)
         && dir_add (dir, name, inode_sector));
   if (!success && inode_sector != 0)
      free_map_release (inode_sector, 1);

   dir_close (dir);

   return success;
}
#endif

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
#ifdef EFILESYS
struct file *
filesys_open (const char *name) {
   // 절대경로를 입력한 경우 root directory 오픈
   if (strcmp(name, "/") == 0)
      return dir_open_root();
   
   struct file * result = NULL;

   // parsing process : 경로 & 파일
   char * target_file = (char *) malloc(NAME_MAX+1);
   struct dir * target_dir = search_target_dir(name, target_file);
   
   // directory path가 유효한 경로인지 확인
   if (target_dir == NULL)
      goto clean;

   struct inode * target_inode = NULL;
   // target_file이 directory path에 존재하는지 확인
   dir_lookup(target_dir, target_file, &target_inode);
   if (target_inode == NULL) 
      goto clean;
   
   // target_file이 soft_link인 경우
   if (inode_is_link(target_inode))
      return filesys_open(inode_change_to_soft_link_path(target_inode));

   result = file_open(target_inode);

clean:
   free(target_file);
   // target_dir == NULL이어도 지장 없음
   dir_close(target_dir);
   return result;
}
#else
struct file *
filesys_open (const char *name) {
   struct inode *inode = NULL;

   struct dir *dir = dir_open_root ();

   if (dir != NULL)
      dir_lookup (dir, name, &inode);
   dir_close (dir);

   return file_open (inode);
}
#endif

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
#ifdef EFILESYS
bool
filesys_remove (const char *name) {
   // 절대경로로 Root Directory를 지우려고 하는 경우
   if (strcmp(name, "/") == 0)
      return false;
   
   // parsing process : 경로 & 파일
   char * whole_input = (char *) malloc(strlen(name) + 1);
   char * target_file = (char *) malloc(sizeof(char)*(NAME_MAX+1));
   struct dir * target_dir;

   if (strlen(name) < NAME_MAX)
      memcpy(whole_input, name, strlen(name) + 1);
   else
      memcpy(whole_input, name, NAME_MAX + 1);

   target_dir = token_target(whole_input, target_file);

   bool success = target_dir != NULL && dir_remove(target_dir, target_file);
   dir_close (target_dir);

   free(whole_input);
   free(target_file);

   return success;
}
#else
bool
filesys_remove (const char *name) {
   struct dir *dir = dir_open_root ();
   bool success = dir != NULL && dir_remove (dir, name);
   dir_close (dir);

   return success;
}
#endif

/* 4-0-4 할당해주고 생성을 위한 값들을 이전에 설정해줬음으로, 그 값들을 바탕으로 FAT 생성 */
/* 4-2-1 free_map과 관련된 함수 모두 수정
       root directory의 위치는 더이상 disk 상에서 sector 1에 위치하지 않는다. cluster 상에
       서 1에 위치한 root directory의 위치를 sector로 변환하여 생성해야한다.
*/
/* Formats the file system. */
static void
do_format (void) {
   printf ("Formatting file system...");

#ifdef EFILESYS
   bool create_success;
   struct dir * root_dir;
   disk_sector_t root_sector;
   disk_sector_t root_inode_sector;

   /* Create FAT and save it to the disk. */
   fat_create ();

   // 4-4-1 inode_disk를 설정하여 root directory를 실제로 생성
   root_sector = cluster_to_sector(ROOT_DIR_CLUSTER);
   create_success = dir_create(root_sector, 2);
   ASSERT (create_success);

   fat_close ();

   // disk에 저장된 root directory를 open & entry 초기화
   root_dir = dir_open_root();
   root_inode_sector = inode_get_inumber(dir_get_inode(root_dir));

   dir_add(root_dir, ".", root_inode_sector);
   dir_add(root_dir, "..", root_inode_sector);

   dir_close(root_dir);
#else
   free_map_create ();
   if (!dir_create (ROOT_DIR_SECTOR, 16))
      PANIC ("root directory creation failed");
   free_map_close ();
#endif

   printf ("done.\n");
}

struct dir *
token_target (char * whole_input, char * target_file) {
   // 'whole_input'을 분석해서 앞으로 작업을 진행할 directory를 리턴
   // 'target_file' : 'whole_input'을 분석한 결과로 앞의 경로에 대한 정보를 제거하고 순수하게 만들
   //               : 것에 대한 이름을 저장
   struct dir * target_dir;
   struct dir * current_dir = thread_current()->work_dir;
   char * command;
   char * remain_command;
   char * parsing_ptr;
   struct inode * check_entry;

   // whole_input과 target_file을 만들어 놓고 함수가 실행되어야 함.
   ASSERT (whole_input != NULL && target_file != NULL);

   // 1. whole_input으로 아무것도 들어오지 않은 경우: 종료
   if (strlen(whole_input) == 0)
      return NULL;
   
   /* 'whole_input'의 절대 or 상대 경로에 따른 디렉토리 정보 저장 */
   if (whole_input[0] == '/') {   // 절대 경로
      target_dir = dir_open_root();
      whole_input += 1;
   } else                         // 상대 경로
      target_dir = dir_reopen(current_dir);

   // 2. whole_input으로 "/"가 들어온 경우: dir 위에서 설정한 대로 리턴, target_file은 변화 없음.
   if (strlen(whole_input) == 0)
      return target_dir;

   // parsing을 진행하며 경로 따라 목표 directory로 이동
   command = strtok_r(whole_input, "/", &parsing_ptr);
   remain_command = strtok_r(NULL, "/", &parsing_ptr);

   while (command != NULL && remain_command != NULL) {
      /* dir에서 command라는 이름의 파일을 검색하여 inode의 정보를 저장 */
      dir_lookup(target_dir, command, &check_entry);

      // dir_lookup을 했는데 해당 경로가 존재하지 않거나,
      // 찾았지만 directory가 아닌 file인 경우
      // + directory는 아니지만 soft link 일 수 있음으로 inode_is_dir 빼줌
      if (check_entry == NULL)
         goto done;
      /* dir의 디렉토리 정보를 메모리에서 해지 */
      dir_close(target_dir);

      /* 찾은 inode가 soft link인 경우 */
      if (inode_is_link(check_entry)) {
         char * soft_file = (char *) malloc(NAME_MAX+1);
         char * soft_link_path = inode_change_to_soft_link_path(check_entry);

         target_dir = search_target_dir(soft_link_path, soft_file);

         if (target_dir == NULL) {
            free(soft_file);
            PANIC("soft_link_path로 찾았는데 없대 -> soft_link_path 이상");
         }

         // target_dir 찾았으니까 check_entry close
         inode_close(check_entry);

         // target_dir에서 soft_file에 해당하는 file의 inode 불러오기
         dir_lookup(target_dir, soft_file, &check_entry);

         // dir_lookup을 했는데 해당 경로가 존재하지 않을 경우
         if (check_entry == NULL)
            goto done;
      }
      // 위의 inode_is_link와 순서 바뀌면 안됨!!!!!
      // 먼저 file 중에서 soft link file인지 확인하고 그 나머지 경우 error
      if (inode_is_dir(check_entry) == false){
         // path search를 위해 open해뒀던 임시 directory close
         dir_close(target_dir);
         // check_entry == NULL이어도 지장 없음
         inode_close(check_entry);
         return NULL;
      }

      /* inode의 디렉토리 정보를 dir에 저장 */
      target_dir = dir_open(check_entry);

      /* token에 검색할 경로 이름 저장 */
      command = remain_command;
      remain_command = strtok_r(NULL, "/", &parsing_ptr);
   }
   /* ideal: token = 실제 저장하고자 하는 file(or directory)의 이름
    *        remain_command = NULL */
   /* token의 파일 이름을 file_name에 저장(file의 이름에는 제한 유지) */
   int file_name_len = NAME_MAX > strlen(command) ? strlen(command) + 1 : NAME_MAX + 1;
   memcpy(target_file, command, file_name_len);
   goto clean;
done :
   // path search를 위해 open해뒀던 임시 directory close
   dir_close(target_dir);
   // check_entry == NULL이어도 지장 없음
   inode_close(check_entry);
   return NULL;
clean:
   /* dir 정보 반환 */
   return target_dir;
}

struct dir *
search_target_dir (char * name, char * file_name) {
   // name과 file_name 모두 NULL이면 안됨
   ASSERT(name != NULL && file_name != NULL);

   char * full_path = (char *) malloc(strlen(name) + 1);

   memcpy(full_path, name, strlen(name) + 1);
   struct dir * target_dir = token_target(full_path, file_name);

   //clean up
   free(full_path);

   return target_dir;
}

bool
filesys_create_dir (const char* name) {
   bool success = false;

   // parsing process : 경로 & 파일
   char * create_dir_name = (char *) malloc(NAME_MAX+1);
   struct dir * target_dir = search_target_dir(name, create_dir_name);
   
   // directory path가 유효한 경로인지 확인
   if (target_dir == NULL)
      goto clean;
   
   struct inode * final_inode;
   disk_sector_t inode_sector;
   dir_lookup (target_dir, create_dir_name, &final_inode);

   // 이미 만들고자 하는 directory가 존재하는 경우
   if (final_inode != NULL) {
      // check_entry == NULL이어도 지장 없음
      inode_close(final_inode);
      goto clean;
   }
   // 실제 생성
   success = (target_dir != NULL
            && (inode_sector = cluster_to_sector(fat_create_chain(0)))
            // 할당받은 inode_sector에 directory용 inode 저장
            && dir_create (inode_sector, 0)
            /* 디렉토리 엔트리에 file_name의 엔트리 추가 */
            && dir_add (target_dir, create_dir_name, inode_sector));
   
   if (!success && inode_sector != 0) {
      fat_remove_chain(sector_to_cluster(inode_sector), 0);
   }
   /* 디렉토리 엔트리에 ‘.’, ‘..’ 파일의 엔트리 추가 */
   struct dir* final_dir = dir_open(inode_open(inode_sector));
   dir_add(final_dir, ".", inode_sector);
   dir_add(final_dir, "..", inode_get_inumber(dir_get_inode(target_dir)));

   dir_close(final_dir);
clean:
   free(create_dir_name);
   // target_dir == NULL이어도 지장 없음
   dir_close(target_dir);
   return success;
}

int
filesys_make_soft_link(const char* target, const char* linkpath) {
   int result = -1;
   // input error case
   if (target == NULL || linkpath == NULL || strlen(target) == 0 || strlen(linkpath) == 0)
      return result;

   // parsing process : 경로 & 파일
   char * file_name = (char *) malloc(NAME_MAX+1);
   struct dir * target_dir = search_target_dir(linkpath, file_name);
   
   // directory path가 유효한 경로인지 확인
   if (target_dir == NULL)
      goto clean;
   
   disk_sector_t inode_sector;
   bool success = ((inode_sector = cluster_to_sector(fat_create_chain(0)))
            // 할당받은 inode_sector에 file용 inode 저장
            && inode_create (inode_sector, 0, true)
            /* 디렉토리 엔트리에 file_name의 엔트리 추가 */
            && dir_add (target_dir, file_name, inode_sector));
   // 실제 inode를 생성해서 directory에 저장하는 것은 실패했지만, fat상으로는 disk 공간을 할당한 경우
   if (!success && inode_sector != 0) {
      fat_remove_chain(sector_to_cluster(inode_sector), 0);
      goto clean;
   }
   // soft link 연결까지 성공
   if (inode_set_soft_link(inode_sector, target))
      result = 0;

clean:
   free(file_name);
   // target_dir == NULL이어도 지장 없음
   dir_close(target_dir);
   return result;
}