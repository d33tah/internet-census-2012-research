#!/usr/bin/pypy

f = open("../by-country.txt")
while True:
  l = f.readline()
  if l == '':
    break
  x = l.split()
  v = x[0].lower()[:-1]
  l, w, o = eval(''.join(x[1:]))
  lw = l+w
  if lw == 0:
    continue
  l_c = int(float(l)/lw*255)
  w_c = int(float(w)/lw*255)
  color = "#%x00%x" % (l_c, w_c)

  f2 = open("BlankMap-World6.svg")
  the_map = f2.read()
  f2.close()

  to_replace = 'id="%s"' % v
  map_file = open("BlankMap-World6.svg","w")
  map_file.write(the_map.replace(to_replace, '%s style="fill:%s"' % (to_replace, color)))
  map_file.close()
