#! /usr/bin/perl -w

use strict;
use warnings;

# using this instead of IO::Socket so we can spoof source IP addresses. This packages requires libpcap and libpcap-devel on your machine.
use Net::RawIP;
use Net::ARP;

use YAML::XS 'LoadFile';


my $config = default_config_values(LoadFile('client.yml'));
print "Target host is " . $config->{server}->{host} . ":" . $config->{server}->{port} . "\n";


my @clients = create_clients ($config);
my $current_packet;
my $attacker_multiplier = $config->{execution}->{attacker_multiplier};
my $attacker_percentage = $config->{execution}->{attacker_percentage};
my $init_packets = $config->{execution}->{init_packets};
print "Starting simulation with attacker_multiplier = $attacker_multiplier, attacker_percentage = $attacker_percentage, init_packets = $init_packets\n";
while (1) {
    $current_packet++;

    my $index;
    my $tmp = int(rand($attacker_multiplier + 1));
    if ($current_packet <= $init_packets || $tmp == 0) {
        $index = int(rand(100 - $attacker_percentage));
    } else {
        $index = 99 - int(rand($attacker_percentage));
    }
    $clients[$index]->send;
}

sub create_clients {
    my $config = shift;

    my @clients;
    for (my $i = 0; $i < 100; $i++) {
        my $type;
        if ($i >= 100 - $config->{execution}->{attacker_percentage}) {
                $type = 'attacker';
        }
        else {
                $type = 'legitimate';
        }

        $clients[$i] = new Net::RawIP({udp => {check => 0}});
        $clients[$i]->set({
            ip => {
                tos => 0,
                saddr => '192.168.70.' . ($i+1),
                daddr => $config->{server}->{host}
            },
            udp => {
                source => 1025 + int(rand(50000)),
                dest => $config->{server}->{port},
                data => $type,
                check => 0
            }
        });
    }

    return @clients;
}


sub default_config_values {
    my $config = shift;

    $config->{server}->{host} = '127.0.0.1' unless defined $config->{server}->{host};
    $config->{server}->{port} = 5000 unless defined  $config->{server}->{port};
    $config->{execution}->{init_packets} = 20000 unless defined  $config->{execution}->{init_packets};
    $config->{execution}->{attacker_percentage} = 20 unless defined  $config->{execution}->{sample_size};
    $config->{execution}->{attacker_multiplier} = 10 unless defined  $config->{execution}->{attacker_multiplier};

    return $config;
}

