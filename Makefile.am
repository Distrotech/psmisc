
SUBDIRS = doc src po icons testsuite

#EXTRA_DIST = config.rpath ABOUT-NLS mkinstalldirs

ACLOCAL_AMFLAGS = -I m4

get-trans:
	rsync -Lrtvz  translationproject.org::tp/latest/psmisc/  po
