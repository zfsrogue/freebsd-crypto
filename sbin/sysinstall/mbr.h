struct field mbr_field[] = {
	{ 0, 25, 31, -1, -1, -1, -1, -1, -1, "Master Boot Record (MBR) editor", F_TITLE, 0, 0},
	{ 4,  8, 30, 30,  2, 49,  2, 50,  2, "Uknown", F_EDIT, 0, 0},
	{ 5, 31,  7, 10,  3,  1,  3,  1,  3, "0", F_EDIT, 0, 0},
	{ 6,  5,  5, 10,  4,  2,  6,  2,  4, "0", F_EDIT, 0, 0},
	{ 6, 14,  5, 10,  5,  2,  6,  3,  5, "0", F_EDIT, 0, 0},
	{ 6, 24,  5, 10,  6,  2,  6,  4,  6, "0", F_EDIT, 0, 0},
	{ 7, 31,  7, 10,  7,  3,  7,  5,  7, "0", F_EDIT, 0, 0},
	{ 8,  5,  5, 10,  8,  6, 10,  6,  8, "0", F_EDIT, 0, 0},
	{ 8, 14,  5, 10,  9,  6, 10,  7,  9, "0", F_EDIT, 0, 0},
	{ 8, 24,  5, 10, 10,  6, 10,  8, 10, "0", F_EDIT, 0, 0},
	{ 9,  9,  6, 10, 11,  7, 12,  9, 11, "0", F_EDIT, 0, 0},
	{ 9, 27,  5, 10, 12,  7, 12, 10, 12, "0", F_EDIT, 0, 0},
	{10, 10, 10, 10, 13, 10, 25, 11, 13, "Not Active", F_EDIT, 0, 0},
	{ 4, 47, 30, 30, 14, 50, 14, 12, 14, "Uknown", F_EDIT, 0, 0},
	{ 5, 70,  7, 10, 15, 13, 15, 13, 15, "0", F_EDIT, 0, 0},
	{ 6, 44,  5, 10, 16, 14, 18, 14, 16, "0", F_EDIT, 0, 0},
	{ 6, 54,  5, 10, 17, 14, 18, 15, 17, "0", F_EDIT, 0, 0},
	{ 6, 64,  5, 10, 18, 14, 18, 16, 18, "0", F_EDIT, 0, 0},
	{ 7, 70,  7, 10, 19, 15, 19, 17, 19, "0", F_EDIT, 0, 0},
	{ 8, 44,  5, 10, 20, 18, 22, 18, 20, "0", F_EDIT, 0, 0},
	{ 8, 54,  5, 10, 21, 18, 22, 19, 21, "0", F_EDIT, 0, 0},
	{ 8, 64,  5, 10, 22, 18, 22, 20, 22, "0", F_EDIT, 0, 0},
	{ 9, 48,  6, 10, 23, 19, 24, 21, 23, "0", F_EDIT, 0, 0},
	{ 9, 66,  5, 10, 24, 20, 24, 22, 24, "0", F_EDIT, 0, 0},
	{10, 49, 10, 10, 25, 22, 37, 23, 25, "Not Active", F_EDIT, 0, 0},
	{14,  8, 30, 30, 26, 12, 26, 24, 26, "Uknown", F_EDIT, 0, 0},
	{15, 31,  7, 10, 27, 25, 27, 25, 27, "0", F_EDIT, 0, 0},
	{16,  5,  5, 10, 28, 26, 30, 26, 28, "0", F_EDIT, 0, 0},
	{16, 14,  5, 10, 29, 26, 30, 27, 29, "0", F_EDIT, 0, 0},
	{16, 24,  5, 10, 30, 26, 30, 28, 30, "0", F_EDIT, 0, 0},
	{17, 31,  7, 10, 31, 27, 31, 29, 31, "0", F_EDIT, 0, 0},
	{18,  5,  5, 10, 32, 30, 34, 30, 32, "0", F_EDIT, 0, 0},
	{18, 14,  5, 10, 33, 30, 34, 31, 33, "0", F_EDIT, 0, 0},
	{18, 24,  5, 10, 34, 30, 34, 32, 34, "0", F_EDIT, 0, 0},
	{19,  9,  6, 10, 35, 31, 36, 33, 35, "0", F_EDIT, 0, 0},
	{19, 27,  5, 10, 36, 31, 36, 34, 36, "0", F_EDIT, 0, 0},
	{20, 10, 10, 10, 37, 34, 49, 35, 37, "Not Active", F_EDIT, 0, 0},
	{14, 47, 30, 30, 38, 24, 38, 36, 38, "Uknown", F_EDIT, 0, 0},
	{15, 70,  7, 10, 39, 37, 39, 37, 39, "0", F_EDIT, 0, 0},
	{16, 44,  5, 10, 40, 38, 42, 38, 40, "0", F_EDIT, 0, 0},
	{16, 54,  5, 10, 41, 38, 42, 39, 41, "0", F_EDIT, 0, 0},
	{16, 64,  5, 10, 42, 38, 42, 40, 42, "0", F_EDIT, 0, 0},
	{17, 70,  7, 10, 43, 39, 43, 41, 43, "0", F_EDIT, 0, 0},
	{18, 44,  5, 10, 44, 42, 46, 42, 44, "0", F_EDIT, 0, 0},
	{18, 54,  5, 10, 45, 43, 46, 43, 45, "0", F_EDIT, 0, 0},
	{18, 64,  5, 10, 46, 43, 46, 44, 46, "0", F_EDIT, 0, 0},
	{19, 48,  6, 10, 47, 43, 48, 45, 47, "0", F_EDIT, 0, 0},
	{19, 66,  5, 10, 48, 44, 48, 46, 48, "0", F_EDIT, 0, 0},
	{20, 49, 10, 10, 49, 46, 50, 47, 49, "Not Active", F_EDIT, 0, 0},
	{22, 15,  2,  2, 50, 36,  1, 48, 50, "OK", F_BUTTON, 0, 0},
	{22, 50,  6,  6,  1, 48, 13, 49,  1, "Cancel", F_BUTTON, 0, 0},
	{2, 15,  11, -1, -1, -1, -1, -1, -1, "Partition 1", F_TITLE, 0, 0},
	{2, 55,  11, -1, -1, -1, -1, -1, -1, "Partition 2", F_TITLE, 0, 0},
	{12, 15, 11, -1, -1, -1, -1, -1, -1, "Partition 3", F_TITLE, 0, 0},
	{12, 55, 11, -1, -1, -1, -1, -1, -1, "Partition 4", F_TITLE, 0, 0},
	{ 4,  2,  5, -1, -1, -1, -1, -1, -1, "Type:", F_TITLE, 0, 0},
	{ 5,  2, 28, -1, -1, -1, -1, -1, -1, "Starting at absolute sector:", F_TITLE, 0, 0},
	{ 6,  2,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{ 6, 11,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{ 6, 21,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{ 7,  2, 26, -1, -1, -1, -1, -1, -1, "Ending at absolute sector:", F_TITLE, 0, 0},
	{ 8,  2,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{ 8, 11,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{ 8, 21,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{ 9, 02,  7, -1, -1, -1, -1, -1, -1, "Size: (", F_TITLE, 0, 0},
	{ 9, 18,  8, -1, -1, -1, -1, -1, -1, "sectors)", F_TITLE, 0, 0},
	{ 9, 33,  2, -1, -1, -1, -1, -1, -1, "Mb", F_TITLE, 0, 0},
	{10,  2,  7, -1, -1, -1, -1, -1, -1, "Status:", F_TITLE, 0, 0},
	{ 4, 41,  5, -1, -1, -1, -1, -1, -1, "Type:", F_TITLE, 0, 0},
	{ 5, 41, 28, -1, -1, -1, -1, -1, -1, "Starting at absolute sector:", F_TITLE, 0, 0},
	{ 6, 41,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{ 6, 51,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{ 6, 61,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{ 7, 41, 26, -1, -1, -1, -1, -1, -1, "Ending at absolute sector:", F_TITLE, 0, 0},
	{ 8, 41,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{ 8, 51,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{ 8, 61,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{ 9, 41,  7, -1, -1, -1, -1, -1, -1, "Size: (", F_TITLE, 0, 0},
	{ 9, 57,  8, -1, -1, -1, -1, -1, -1, "sectors)", F_TITLE, 0, 0},
	{ 9, 72,  2, -1, -1, -1, -1, -1, -1, "Mb", F_TITLE, 0, 0},
	{10, 41,  7, -1, -1, -1, -1, -1, -1, "Status:", F_TITLE, 0, 0},
	{14, 02,  5, -1, -1, -1, -1, -1, -1, "Type:", F_TITLE, 0, 0},
	{15, 02, 28, -1, -1, -1, -1, -1, -1, "Starting at absolute sector:", F_TITLE, 0, 0},
	{16,  2,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{16, 11,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{16, 21,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{17, 02, 26, -1, -1, -1, -1, -1, -1, "Ending at absolute sector:", F_TITLE, 0, 0},
	{18, 02,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{18, 11,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{18, 21,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{19, 02,  7, -1, -1, -1, -1, -1, -1, "Size: (", F_TITLE, 0, 0},
	{19, 18,  8, -1, -1, -1, -1, -1, -1, "sectors)", F_TITLE, 0, 0},
	{19, 33,  2, -1, -1, -1, -1, -1, -1, "Mb", F_TITLE, 0, 0},
	{20, 02,  7, -1, -1, -1, -1, -1, -1, "Status:", F_TITLE, 0, 0},
	{14, 41,  5, -1, -1, -1, -1, -1, -1, "Type:", F_TITLE, 0, 0},
	{15, 41, 28, -1, -1, -1, -1, -1, -1, "Starting at absolute sector:", F_TITLE, 0, 0},
	{16, 41,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{16, 51,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{16, 61,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{17, 41, 26, -1, -1, -1, -1, -1, -1, "Ending at absolute sector:", F_TITLE, 0, 0},
	{18, 41,  2, -1, -1, -1, -1, -1, -1, "C:", F_TITLE, 0, 0},
	{18, 51,  2, -1, -1, -1, -1, -1, -1, "H:", F_TITLE, 0, 0},
	{18, 61,  2, -1, -1, -1, -1, -1, -1, "S:", F_TITLE, 0, 0},
	{19, 41,  7, -1, -1, -1, -1, -1, -1, "Size: (", F_TITLE, 0, 0},
	{19, 57,  8, -1, -1, -1, -1, -1, -1, "sectors)", F_TITLE, 0, 0},
	{19, 72,  2, -1, -1, -1, -1, -1, -1, "Mb", F_TITLE, 0, 0},
	{20, 41,  7, -1, -1, -1, -1, -1, -1, "Status:", F_TITLE, 0, 0}
};
