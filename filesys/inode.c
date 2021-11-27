#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/fat.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	// start : file에 대한 inode인 경우 파일의 실제 내용을, directory에 대한 inode인 경우 directory entry가 저장된 sector 번호를 나타냄.
	/* 한양대 : file에 대한 inode인지, directory에 대한 inode인지 구분하는 property 필요 */
	disk_sector_t start;                /* First data sector. */
	// length : 저장된 공간의 길이(sector 단위)
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	uint32_t unused[125];               /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list.(open_inodes) */
	// sector : disk에서 inode_disk가 위치한 sector
	disk_sector_t sector;               /* Sector number of disk location. */
	// open_cnt : 어딘가에서 inode가 open되어 있는데 함부로 닫으면 안되니까 그걸 방지하기 위한 변수
	int open_cnt;                       /* Number of openers. */
	// removed : 삭제해도 되는지 여부 확인에 사용
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	// data : disk에 저장된 것을 필요할 때마다 매번 디스크 read를 하면 오래 걸리니까 physical memory에 올려놓음.
	// inode_close가 호출되어서 이 inode가 더이상 필요 없어지면 physical memory로 올린 걸 다시 disk에 입력해야함.
	struct inode_disk data;             /* Inode content. */
};

/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
 /* 4-2-2 byte_to_sector에서 모든 file을 위한 sector는 연결되어 있는 것으로 가정하고 계산한다.
		  FAT에서는 linked-list를 이용해 하나의 file을 위한 sector를 떨어트려 놓을 수 있음으로
		  이를 적용한다.
 */
#ifdef EFILESYS
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
	ASSERT (inode != NULL);
	if (pos < inode->data.length)
		return get_sector_using_fat(sector_to_cluster(inode->data.start), pos);
	else
		return -1;
}
#else
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
	ASSERT (inode != NULL);
	if (pos < inode->data.length)
		return inode->data.start + pos / DISK_SECTOR_SIZE;
	else
		return -1;
}
#endif
/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
 /* 4-2-4 inode_create를 FAT style로 변경 */
 /* 한양대 : dir_create(), filesys_create()에서 모두 inode_create()를 호출
		   : inode_create에서 해당 inode가 directory 용도인지 file 용도인지
		   : 를 확인하기 위해 parameter로 bool 값을 하나 더 받도록 수정
 */
bool
inode_create (disk_sector_t sector, off_t length) {
	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		// inode_disk 구조체 초기화 (start, length, magic)
		size_t sectors = bytes_to_sectors (length);      // length (byte)를 섹터 단위(개수)로 변환
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
#ifdef EFILESYS
		static char zeros[DISK_SECTOR_SIZE];

		// last_clst가 가리키고 있는 empty list의 제일 첫번째 cluster에 EOChain을 넣고,
		//  그 cluster return
		cluster_t start = fat_create_chain(0);
		// start에 매칭되는 disk 상의 sector를 0으로 채움
		disk_write(filesys_disk, cluster_to_sector(start), zeros);

		disk_inode->start = cluster_to_sector(start);
		disk_write (filesys_disk, sector, disk_inode);
		cluster_t clst_length = sectors / SECTORS_PER_CLUSTER;

		// file을 위한 cluster를 할당하는 중에 더이상 할당하지 못하게 된 경우,
		// 지금까지 만들었던 chain이 없었던 처음으로 다시 돌려야함. 이를 위해
		// chain의 처음을 기억하고 이후 fat_remove_chain(__, 0);을 사용.
		cluster_t original_start = start;

		while (clst_length > 1) {
			start = fat_create_chain(start);
			if (start == 0) {	// 중간에 empty cluster 찾지 못한 경우
				fat_remove_chain(original_start, 0);
				free (disk_inode);
				return success;
			}
			clst_length--;
			disk_write(filesys_disk, cluster_to_sector(start), zeros);
		}
		free (disk_inode);
		success = true;
		return success;
#else
		// free_map_allocate()를 FAT 기반으로 대체
		// 필요한 길이만큼 fat_create_chain() 반복
		if (free_map_allocate (sectors, &disk_inode->start)) {
			// 디스크의 sector 위치에 inode_disk 구조체 입력 (동일?)
			disk_write (filesys_disk, sector, disk_inode);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;

				// 디스크의 start 위치부터 sectors만큼 0으로 padding (동일? 클러스터 단위로 변환)
				for (i = 0; i < sectors; i++) 
					disk_write (filesys_disk, disk_inode->start + i, zeros); 
			}
			success = true; 
		} 
		free (disk_inode);	
		return success;
#endif
	}
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) {
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen (inode);
			return inode; 
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	disk_read (filesys_disk, inode->sector, &inode->data);
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	disk_write (filesys_disk, inode->sector, &inode->data);

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
#ifdef EFILESYS
			fat_remove_chain(sector_to_cluster(inode->sector), 0);
			fat_remove_chain(sector_to_cluster(inode->data.start), 0);
#else
			// HS. map 기반의 제거 -> FAT로 변경
			free_map_release (inode->sector, 1);
			free_map_release (inode->data.start,
				bytes_to_sectors (inode->data.length)); 
#endif
		}
		free (inode); 
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {
	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

	while (size > 0) {
		/* Disk sector to read, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Read full sector directly into caller's buffer. */
			disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
		} else {
			/* Read sector into bounce buffer, then partially copy
			 * into caller's buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			disk_read (filesys_disk, sector_idx, bounce);
			memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	free (bounce);

	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
 /* 4-3-0 file growth  */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
    	off_t offset) {
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	uint8_t *bounce = NULL;

	if (inode->deny_write_cnt)
		return 0;

	if (inode->data.length < size + offset) {
		//cluster_t current_length = bytes_to_sectors(inode->data.length) / SECTORS_PER_CLUSTER;
		//cluster_t total_length = bytes_to_sectors(size + offset) / SECTORS_PER_CLUSTER;
		cluster_t current_length = DIV_ROUND_UP (inode->data.length, DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER);
		cluster_t total_length = DIV_ROUND_UP (size + offset, DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER);
		cluster_t need_length = total_length - current_length;

		if (inode->data.length == 0)
			need_length--;

		//printf("hello2\n");

		cluster_t end_clst = sector_to_cluster(inode->data.start);

		while(fat_get(end_clst) != EOChain)
			end_clst = fat_get(end_clst);

		// while(current_length > 1) {
		//    end_clst = fat_get(end_clst);
		//    current_length--;
		// }
		// data.length가 0인 경우?
		// cluster_t extend_clst = inode->data.length ? new_clst - old_clst : new_clst - old_clst - 1;

		while (need_length > 0) {
			end_clst = fat_create_chain(end_clst);
			need_length--;
		}
	}
	inode->data.length = size + offset;

	while (size > 0) {
		/* Sector to write, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Write full sector directly to disk. */
			disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
		} else {
			/* We need a bounce buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}

			/* If the sector contains data before or after the chunk
			   we're writing, then we need to read in the sector
			   first.  Otherwise we start with a sector of all zeros. */
			if (sector_ofs > 0 || chunk_size < sector_left) 
				disk_read (filesys_disk, sector_idx, bounce);
			else
				memset (bounce, 0, DISK_SECTOR_SIZE);
			memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
			disk_write (filesys_disk, sector_idx, bounce); 
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}
	free (bounce);

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) {
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
   	return inode->data.length;
}
