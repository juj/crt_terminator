#ifndef VEC_H
#define VEC_H

#include <stdlib.h>

template<class T>
class vec
{
public:
	int sz, cap;
	T *data;
	vec():sz(0),cap(0),data(0) {}
	~vec() { free(data); }
	void push_n(unsigned int n, const T &val)
	{
		if (sz + n > cap)
		{
			cap = (sz+n)+16;
			data = (T*)realloc(data, sizeof(T)*cap);
		}
		for(unsigned int i = 0; i < n; ++i)
			data[sz++] = val;
	}
	void push(const T &val)
	{
		if (sz >= cap)
		{
			cap = cap*2+16;
			data = (T*)realloc(data, sizeof(T)*cap);
		}
		data[sz++] = val;
	}
	int find(const T &val)
	{
		for(int i = 0; i < sz; ++i)
			if (data[i] == val) return i;
		return -1;
	}
	void sort()
	{
		for(int i = 0; i < sz; ++i)
			for(int j = i+1; j < sz; ++j)
				if (data[j] < data[i])
				{
					T tmp = data[j]; data[j] = data[i]; data[i] = tmp;
				}
	}
	int size() const { return sz; }
	T &operator[](int idx) { return data[idx]; }
	const T &operator[](int idx) const { return data[idx]; }
	void clear() { sz = 0; }
}

#endif
