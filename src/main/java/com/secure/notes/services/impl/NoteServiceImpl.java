package com.secure.notes.services.impl;

import com.secure.notes.models.Note;
import com.secure.notes.repositories.NoteRepository;
import com.secure.notes.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NoteServiceImpl implements NoteService {
    @Autowired
    private NoteRepository noteRepository;

    @Override
    public Note createNoteForUser(String username, String content) {
        Note note = new Note();
        note.setContent(content);
        note.setOwnerUsername(username);
        Note savedNote = noteRepository.save(note);
        return savedNote;
    }

    @Override
    public Note updateNoteForUser(Long noteId, String content, String username) {
        Note note=noteRepository.findById(noteId).orElseThrow(()->new RuntimeException("Note not found"));
        note.setContent(content);
        //노트 객체에 id가 포함되어 있으므로 저장이 아닌 업데이트가 된다
        Note updatedNote=noteRepository.save(note);
        return updatedNote;
    }

    @Override
    public void deleteNoteForUser(Long noteId, String username) {
        noteRepository.deleteById(noteId);

    }

    @Override
    public List<Note> getNotesForUser(String username) {
        List<Note> personalNotes=noteRepository.findByOwnerUsername(username);
        return personalNotes;
    }
}
