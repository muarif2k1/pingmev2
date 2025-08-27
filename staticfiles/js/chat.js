class ChatApp {
    constructor() {
        this.messageRefreshInterval = 5000; // 5 seconds
        this.currentChatId = null;
        this.currentRoomId = null;
        this.isAtBottom = true;
        
        this.initializeEventListeners();
        this.startPeriodicUpdates();
    }
    
    initializeEventListeners() {
        // Message form submission
        $(document).on('submit', '#message-form', (e) => {
            e.preventDefault();
            this.sendMessage(e.target);
        });
        
        // Auto-resize textarea
        $(document).on('input', 'textarea', function() {
            this.style.height = 'auto';
            this.style.height = this.scrollHeight + 'px';
        });
        
        // Mark messages as read when scrolling to bottom
        $(document).on('scroll', '#messages-container', () => {
            this.checkScrollPosition();
        });
        
        // Keyboard shortcuts
        $(document).on('keydown', (e) => {
            // Ctrl/Cmd + Enter to send message
            if ((e.ctrlKey || e.metaKey) && e.keyCode === 13) {
                $('#message-form').submit();
            }
        });
    }
    
    sendMessage(form) {
        const formData = new FormData(form);
        const content = formData.get('content').trim();
        
        if (!content) return;
        
        const submitBtn = $(form).find('button[type="submit"]');
        const originalText = submitBtn.html();
        
        submitBtn.html('<i class="fas fa-spinner fa-spin"></i>').prop('disabled', true);
        
        $.ajax({
            url: '/send-message/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: (response) => {
                if (response.success) {
                    this.addMessageToUI(response, true);
                    form.reset();
                } else {
                    this.showNotification('Error: ' + response.message, 'error');
                }
            },
            error: () => {
                this.showNotification('Network error. Please try again.', 'error');
            },
            complete: () => {
                submitBtn.html(originalText).prop('disabled', false);
                $(form).find('input[name="content"]').focus();
            }
        });
    }
    
    addMessageToUI(messageData, isOwn) {
        const messageClass = isOwn ? 'message-own' : 'message-other';
        const container = $('#messages-container');
        
        const messageHTML = this.buildMessageHTML(messageData, messageClass, isOwn);
        container.append(messageHTML);
        
        if (this.isAtBottom) {
            this.scrollToBottom();
        }
        
        // Play notification sound for received messages
        if (!isOwn) {
            this.playNotificationSound();
        }
    }
    
    buildMessageHTML(data, messageClass, isOwn) {
        const userInfo = isOwn ? '' : `
            <div class="d-flex align-items-center mb-1">
                <small class="text-muted fw-bold">${data.username}</small>
            </div>
        `;
        
        const messageActions = isOwn ? `
            <div class="message-actions" style="display: none;">
                <button class="btn btn-xs btn-outline-secondary me-1" onclick="editMessage('${data.message_id}', '${data.content}')">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn btn-xs btn-outline-danger" onclick="deleteMessage('${data.message_id}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        ` : '';
        
        return `
            <div class="message-bubble ${messageClass}" data-message-id="${data.message_id}">
                ${userInfo}
                <div class="message-content">${data.content}</div>
                <small class="text-muted message-time">${data.timestamp}</small>
                ${messageActions}
            </div>
        `;
    }
    
    checkScrollPosition() {
        const container = $('#messages-container')[0];
        this.isAtBottom = container.scrollHeight - container.clientHeight <= container.scrollTop + 1;
    }
    
    scrollToBottom() {
        const container = $('#messages-container')[0];
        container.scrollTop = container.scrollHeight;
    }
    
    playNotificationSound() {
        // Create and play a simple notification sound
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = 800;
        oscillator.type = 'sine';
        
        gainNode.gain.setValueAtTime(0, audioContext.currentTime);
        gainNode.gain.linearRampToValueAtTime(0.3, audioContext.currentTime + 0.1);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.5);
    }
    
    startPeriodicUpdates() {
        // Update unread counts every 30 seconds
        setInterval(() => {
            this.updateUnreadCounts();
        }, 30000);
        
        // Refresh messages every 5 seconds if in a chat
        setInterval(() => {
            this.refreshCurrentChat();
        }, this.messageRefreshInterval);
    }
    
    updateUnreadCounts() {
        $.get('/api/unread-counts/', (data) => {
            // Update private chat badges
            Object.keys(data.private_chats).forEach(chatId => {
                $(`.chat-badge[data-chat-id="${chatId}"]`).text(data.private_chats[chatId]).show();
            });
            
            // Update room badges
            Object.keys(data.rooms).forEach(roomId => {
                $(`.room-badge[data-room-id="${roomId}"]`).text(data.rooms[roomId]).show();
            });
        });
    }
    
    refreshCurrentChat() {
        if (this.currentChatId) {
            this.refreshMessages(`/api/chat/${this.currentChatId}/messages/`);
        } else if (this.currentRoomId) {
            this.refreshMessages(`/api/room/${this.currentRoomId}/messages/`);
        }
    }
    
    refreshMessages(url) {
        $.get(url, (data) => {
            const currentMessages = $('#messages-container .message-bubble').map(function() {
                return $(this).data('message-id');
            }).get();
            
            data.messages.forEach((message) => {
                if (!currentMessages.includes(message.id)) {
                    this.addMessageToUI({
                        message_id: message.id,
                        content: message.content,
                        username: message.username,
                        timestamp: new Date(message.timestamp).toLocaleTimeString('en-US', {
                            hour: '2-digit',
                            minute: '2-digit'
                        })
                    }, message.is_own);
                }
            });
        });
    }
    
    showNotification(message, type) {
        const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
        const notification = $(`
            <div class="alert ${alertClass} alert-dismissible fade show position-fixed" 
                 style="top: 100px; right: 20px; z-index: 9999;" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `);
        
        $('body').append(notification);
        
        setTimeout(() => {
            notification.fadeOut();
        }, 5000);
    }
}

// Initialize chat app when document is ready
$(document).ready(() => {
    window.chatApp = new ChatApp();
});