package com.gkcontas.documents.web;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.http.HttpSessionListener;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The live HTTP sessions of this instance, by id, so a back-channel logout can
 * end one directly. The servlet API has no lookup by id; these listeners keep
 * the index, including across the id change made at login against session
 * fixation. With several instances the sessions belong in a shared store
 * (Spring Session), which can delete by id.
 */
@Component
public class LocalSessions implements HttpSessionListener, HttpSessionIdListener {

    private final Map<String, HttpSession> sessions = new ConcurrentHashMap<>();

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        sessions.put(event.getSession().getId(), event.getSession());
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        sessions.remove(event.getSession().getId());
    }

    @Override
    public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
        sessions.remove(oldSessionId);
        sessions.put(event.getSession().getId(), event.getSession());
    }

    /** @return whether a live session with this id existed */
    public boolean invalidate(String sessionId) {
        HttpSession session = sessions.remove(sessionId);
        if (session == null) {
            return false;
        }
        try {
            session.invalidate();
            return true;
        } catch (IllegalStateException alreadyInvalidated) {
            return false;
        }
    }
}
