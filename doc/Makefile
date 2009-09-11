#
# Needs fixes! 
# Makefile,v 2.3 2003/02/17 13:12:57 kr Exp
#

DOCUMENT=papillon

# Programs
ASPELL=aspell
DVIPS=dvips
LATEX=latex -interaction=batchmode
BIBTEX=bibtex
PDFLATEX=pdflatex -interaction=batchmode
PDFTEX=pdftex
THUMBPDF=thumbpdf
ENV=mylayout.sty mydefs.sty refs.bib

ps:	$(DOCUMENT).ps
dvi:	$(DOCUMENT).dvi
pdf:	$(DOCUMENT).pdf

all:	dvi

dist:	dvi ps pdf

%.eps:	%.eps.Z
	zcat $< > $@

$(DOCUMENT).ps:	$(DOCUMENT).dvi
	$(DVIPS) -o $(DOCUMENT).ps $(DOCUMENT).dvi 

$(DOCUMENT).dvi: $(DOCUMENT).tex $(ENV) 
	$(LATEX) $(DOCUMENT) 
	$(BIBTEX) $(DOCUMENT)
	$(LATEX) $(DOCUMENT) 
	$(LATEX) $(DOCUMENT) 

$(DOCUMENT).pdf: $(DOCUMENT).tex $(ENV) 
	$(PDFLATEX) $(DOCUMENT) 
	$(BIBTEX) $(DOCUMENT)
	$(PDFLATEX) $(DOCUMENT)
	$(PDFLATEX) $(DOCUMENT)
	$(THUMBPDF) $(DOCUMENT)
	$(PDFLATEX) $(DOCUMENT)
	rm -f thumb*.png thumbpdf.* thumbdta.*

clean:
	rm -f $(DOCUMENT).aux $(DOCUMENT).log 
	rm -f $(DOCUMENT).bbl $(DOCUMENT).blg
	rm -f $(DOCUMENT).toc $(DOCUMENT).dvi
	rm -f $(DOCUMENT).out $(DOCUMENT).lof
	rm -f *~ *.bak *.log *.bbl *.aux *.blg
	rm -f thumb*.png thumbpdf.* thumbdta.*
	rm -f papillon-logo.eps

distclean:	clean
	rm -f $(DOCUMENT).ps $(DOCUMENT).pdf

spellcheck: $(DOCUMENT).tex
	env LANG=en_GB $(ASPELL) --repl=./aspell.en.prepl -t --lang=en_GB \
        --personal=./aspell.en.pws --sug-mode=normal -c $(DOCUMENT).tex
