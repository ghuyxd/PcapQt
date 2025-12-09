# -*- coding: utf-8 -*-
"""
DNS Resolver utility for hostname resolution.
Provides caching and async DNS resolution.
"""

import socket
import threading
from collections import OrderedDict
from datetime import datetime, timedelta


class DNSResolver:
    """DNS resolver with caching for efficient hostname lookups."""
    
    def __init__(self, cache_size=1000, cache_ttl=300):
        """
        Initialize DNS resolver.
        
        Args:
            cache_size: Maximum number of cached entries
            cache_ttl: Cache time-to-live in seconds
        """
        self._cache = OrderedDict()
        self._cache_size = cache_size
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        self._enabled = True
        
        # DNS responses learned from captured packets
        self._dns_cache = {}  # domain -> IP mapping from DNS responses
        
    def set_enabled(self, enabled):
        """Enable or disable DNS resolution."""
        self._enabled = enabled
        
    def is_enabled(self):
        """Check if DNS resolution is enabled."""
        return self._enabled
    
    def resolve_ip(self, ip_address):
        """
        Resolve IP address to hostname.
        
        Args:
            ip_address: IP address string
            
        Returns:
            Hostname string or original IP if resolution fails
        """
        if not self._enabled:
            return ip_address
            
        # Check cache first
        cached = self._get_from_cache(ip_address)
        if cached is not None:
            return cached
            
        # Try reverse DNS lookup
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            self._add_to_cache(ip_address, hostname)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            # Cache the failure to avoid repeated lookups
            self._add_to_cache(ip_address, ip_address)
            return ip_address
    
    def resolve_ip_async(self, ip_address, callback):
        """
        Resolve IP address asynchronously.
        
        Args:
            ip_address: IP address to resolve
            callback: Function to call with result (hostname).
                      WARNING: Callback is invoked from a worker thread.
                      If updating UI, use Qt signals with QueuedConnection.
        """
        def _resolve():
            result = self.resolve_ip(ip_address)
            if callback:
                callback(ip_address, result)
        
        thread = threading.Thread(target=_resolve, daemon=True)
        thread.start()
    
    def add_dns_response(self, domain, ip_address):
        """
        Learn DNS mapping from captured DNS response.
        
        Args:
            domain: Domain name
            ip_address: Resolved IP address
        """
        with self._lock:
            self._dns_cache[domain.lower()] = ip_address
            # Also add reverse mapping
            self._add_to_cache(ip_address, domain)
    
    def get_domain_for_ip(self, ip_address):
        """
        Get domain name from learned DNS responses.
        
        Args:
            ip_address: IP address
            
        Returns:
            Domain name or None
        """
        with self._lock:
            for domain, ip in self._dns_cache.items():
                if ip == ip_address:
                    return domain
        return None
    
    def _get_from_cache(self, key):
        """Get value from cache if not expired."""
        with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if datetime.now() - timestamp < timedelta(seconds=self._cache_ttl):
                    # Move to end (LRU)
                    self._cache.move_to_end(key)
                    return value
                else:
                    # Expired
                    del self._cache[key]
        return None
    
    def _add_to_cache(self, key, value):
        """Add value to cache with LRU eviction."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (value, datetime.now())
            
            # Evict oldest if over limit
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
    
    def clear_cache(self):
        """Clear all cached DNS entries."""
        with self._lock:
            self._cache.clear()
            self._dns_cache.clear()
    
    def get_cache_stats(self):
        """Get cache statistics."""
        with self._lock:
            return {
                'size': len(self._cache),
                'dns_entries': len(self._dns_cache),
                'max_size': self._cache_size,
                'ttl': self._cache_ttl
            }


# Global DNS resolver instance
_global_resolver = None


def get_dns_resolver():
    """Get the global DNS resolver instance."""
    global _global_resolver
    if _global_resolver is None:
        _global_resolver = DNSResolver()
    return _global_resolver
