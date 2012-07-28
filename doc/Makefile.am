
man_MANS = killall.1 peekfd.1 prtstat.1 pstree.1
EXTRA_MANS = 

if WANT_FUSER
  man_MANS += fuser.1
else
  EXTRA_MANS += fuser.1
endif

EXTRA_DIST = $(man_MANS) $(EXTRA_MANS)
