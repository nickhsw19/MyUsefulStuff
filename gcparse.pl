#!/usr/bin/perl
#
#       Used to parse up the gc_stats logs
#       which are annoying badly formatted

use     strict;
#use     Text::Table;


my      @old;
my      @new;
my      @perm;
my      @real;
my      @clocktime;
my      $logtime;

sub parseformat1 () {   # Used to format

        my      $gcreal;
        my      $line;

        $gcreal = @_[0];
        $gcreal =~ s/.*real=(.*?) .*$/$1/;
        push @real, $gcreal;

        if (@_[0] =~ /PSOldGen/oi) {
                $line = @_[0];
                $line =~ s/.*\[(PSOldGen:.*?)\].*$/$1/;
                $line =~ s/.*[0-9]K->([0-9]*?K).*$/$1/;
                $line =~ s/K//;
                push @old, $line;
        }
        if (@_[0] =~ /ParOldGen/oi) {
                $line = @_[0];
                $line =~ s/.*\[(ParOldGen:.*?)\].*$/$1/;
                $line =~ s/.*[0-9]K->([0-9]*?K).*$/$1/;
                $line =~ s/K//;
                push @old, $line;
        }

        if ($_ =~ /PSYoungGen/oi) {     # This probably needs to be changed
                $line = @_[0];
                $line =~ s/.*\[(PSYoungGen:.*?)\].*$/$1/;
                $line =~ s/.*[0-9]K->([0-9]*?K).*$/$1/;
                $line =~ s/K//;
                push @new, $line;
        }

        if ($_ =~ /PSPermGen/oi) {
                $line = @_[0];
                $line =~ s/.*\[(PSPermGen:.*?)\].*$/$1/;
                $line =~ s/.*[0-9]K->([0-9]*?K).*$/$1/;
                $line =~ s/K//;
                push @perm, $line;
        }
        if ($_ =~ /Metaspace/oi) {
                $line = @_[0];
                $line =~ s/.*\[(Metaspace:.*?)\].*$/$1/;
                $line =~ s/.*[0-9]K->([0-9]*?K).*$/$1/;
                $line =~ s/K//;
                push @perm, $line;
        }
}

#
#       Entry point here
#

while (<STDIN>) {
        chomp;
        if ($_ =~ /Full GC /oi) {
                #
                #       Clocktime format varies annoying
                #
                $logtime = (split) [0];
                $logtime =~ s/T/ /;
                $logtime =~ s/(.*)\+.*$/$1/;
                push @clocktime, $logtime;

                if ($_ =~ /AdaptiveSizeStart/oi) {      # Long multiline
                        $_ = <STDIN>;
                        $_ = <STDIN>;
                        chomp;
                }
                &parseformat1($_);
        }

}

print   "Full GC stats\n";
#my      $tb = Text::Table->new( "Time", "Old Gen (K)", "New Gen (K)", "Perm Gen (K)", "Real secs");
printf("%-25s%22s%22s%22s%20s\n", "Time", "Old Gen (K)", "New Gen (K)", "Perm Gen (K)", "Real secs");

for (my $i = 0; $i < (scalar @old); $i++) {
        #$tb->load( [$clocktime[$i], $old[$i], $new[$i], $perm[$i], $real[$i] ]);
        printf("%20s%20d%20d%20d%23.2f\n", $clocktime[$i], $old[$i], $new[$i], $perm[$i], $real[$i]);
}


