/* strlcpy and strlcat implementations for systems that don't have them */
#ifndef HAVE_STRLCPY
static inline size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t src_len = strlen(src);
	if (size == 0) return src_len;
	
	size_t copy_len = (src_len < size - 1) ? src_len : size - 1;
	memcpy(dst, src, copy_len);
	dst[copy_len] = '\0';
	return src_len;
}
#endif

#ifndef HAVE_STRLCAT
static inline size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t dst_len = strlen(dst);
	size_t src_len = strlen(src);
	
	if (dst_len >= size) return dst_len + src_len;
	
	size_t copy_len = (src_len < size - dst_len - 1) ? src_len : size - dst_len - 1;
	memcpy(dst + dst_len, src, copy_len);
	dst[dst_len + copy_len] = '\0';
	return dst_len + src_len;
}
#endif