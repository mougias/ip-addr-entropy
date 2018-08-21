#! /usr/bin/perl -w

use strict;
use warnings;

use IO::Socket::INET;
use YAML::XS 'LoadFile';


my $config = default_config_values(LoadFile('server.yml'));

my $sock = IO::Socket::INET->new(
    Proto => 'udp',
    LocalAddr => $config->{server}->{host},
    LocalPort => $config->{server}->{port}
) or die "Could not create socket: $!\n";
#$| = 1;

print 'Listening on ' . $config->{server}->{host} . ':' . $config->{server}->{port} . "\n";
print 'Sample size: ' . $config->{execution}->{sample_size} . ' packets' . "\n";
print 'Initialization samples: ' . $config->{execution}->{init_samples} . "\n";
print 'Entropy threshold: ' . $config->{execution}->{threshold} . "\n";



# ===============
# MAIN LOOP START
# ===============
my $packet;
my $current_sample = 0;
my $current_packet = 0;
my $sample_ips;
my $average_entropy = 0;

while (1) {
    $sock->recv($packet, 1024);
    $current_packet++;
    my $ip = $sock->peerhost;
    $sample_ips->{$ip} = 0 unless defined $sample_ips->{$ip};
    $sample_ips->{$ip}++;
    if ($current_packet == $config->{execution}->{sample_size}) {
        $current_packet = 0;
        $current_sample++;
        my $entropy = calculate_entropy($sample_ips);
        $sample_ips = undef;
        if ($current_sample > $config->{execution}->{init_samples} && $entropy < $average_entropy * $config->{execution}->{threshold} ) {
            print "Suspected DDoS attack\n";
        } 
        
        $average_entropy = ($average_entropy * ($current_sample - 1) + $entropy) / $current_sample;
        if ($current_sample == $config->{execution}->{init_samples}) {
            print "Initialization complete with average entropy = $average_entropy\n";
        }
    }
}

=pod
=head1 Simpson Diversity Index

http://www.statisticshowto.com/simpsons-diversity-index/
=cut
sub calculate_entropy {
    my $sample = shift;
    
    my $sum = 0;
    my $total = 0; # at the end of the loop this should be equal to $config->{execution}->{sample_size}
    foreach my $ip (keys %$sample) {
        $sum += $sample->{$ip} * ($sample->{$ip} - 1);
        $total += $sample->{$ip};
    }
    $total *= ($total - 1);
    return 1 - ($sum / $total);
}



sub default_config_values {
    my $config = shift;

    $config->{server}->{host} = '0.0.0.0' unless defined $config->{server}->{host};
    $config->{server}->{port} = 5000 unless defined  $config->{server}->{port};
    $config->{execution}->{init_samples} = 10 unless defined  $config->{execution}->{init_samples};
    $config->{execution}->{sample_size} = 100 unless defined  $config->{execution}->{sample_size};
    
    $config->{execution}->{threshold} = 0.80 unless defined  $config->{execution}->{threshold};
    ($config->{execution}->{threshold} <= 0.99 && $config->{execution}->{threshold} >= 0.01) or die('Threshold must be between 0.01 and 0.99');
    
    
    return $config;
}